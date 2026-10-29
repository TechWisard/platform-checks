using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RuntimeProbe;

internal sealed class CaseResult
{
    public int index { get; set; }
    public bool process_started { get; set; }
    public bool exit_observed { get; set; }
    public uint? exit_code { get; set; }
    public bool stdout_matches { get; set; }
    public bool stderr_matches { get; set; }
    public bool window_observed { get; set; }
    public bool window_responsive { get; set; }
    public bool close_sent { get; set; }
    public bool job_empty { get; set; }
    public bool cleanup_verified { get; set; }
    public bool forced_termination { get; set; }
    public int error { get; set; }
    public bool passed { get; set; }
}

internal static class RunnerProcess
{
    internal static bool InteractiveSessionReady()
    {
        if (!Native.ProcessIdToSessionId(Native.GetCurrentProcessId(), out uint session) || session == 0) return false;
        IntPtr state = IntPtr.Zero;
        try
        {
            if (!Native.WTSQuerySessionInformationW(IntPtr.Zero, session, 8, out state, out uint count) || state == IntPtr.Zero || count != 4 || Marshal.ReadInt32(state) != 0) return false;
        }
        finally { if (state != IntPtr.Zero) Native.WTSFreeMemory(state); }
        IntPtr station = Native.GetProcessWindowStation();
        return station != IntPtr.Zero && Native.GetUserObjectInformationW(station, 1, out var flags, (uint)Marshal.SizeOf<Native.UserObjectFlags>(), out _) && (flags.dwFlags & 1) != 0;
    }

    internal static CaseResult ConsoleCase(string file, string argument, int index, int expectedExit, string stdoutHash, string stderrHash)
    {
        var result = new CaseResult { index = index };
        OwnedProcess? process = null;
        try
        {
            process = OwnedProcess.Create(file, argument, false, result);
            process.WaitExit(TimeSpan.FromSeconds(10));
            result.exit_observed = true; result.exit_code = process.ExitCode();
            result.stdout_matches = process.Matches(true, stdoutHash);
            result.stderr_matches = process.Matches(false, stderrHash);
            result.passed = result.exit_code == expectedExit && result.stdout_matches && result.stderr_matches;
        }
        catch (ProbeFailure failure) { result.error = failure.Code; }
        catch (Win32Exception failure) { result.error = failure.NativeErrorCode; }
        catch { result.error = 599; }
        finally { if (process is not null) process.Cleanup(result); }
        result.passed &= result.cleanup_verified && !result.forced_termination && result.error == 0;
        return result;
    }

    internal static CaseResult WindowCase(string file, string windowClass)
    {
        var result = new CaseResult { index = 4 };
        OwnedProcess? process = null;
        try
        {
            process = OwnedProcess.Create(file, "", true, result);
            IntPtr window = IntPtr.Zero;
            var wait = Stopwatch.StartNew();
            var stable = new Stopwatch();
            while (wait.Elapsed < TimeSpan.FromSeconds(30))
            {
                Wire.Need(!process.Exited() && !process.OutputOverflow, 510);
                IntPtr observed = FindWindow(process.Pid, windowClass);
                if (observed != IntPtr.Zero)
                {
                    if (window != observed) { window = observed; stable.Restart(); }
                    if (stable.Elapsed >= TimeSpan.FromSeconds(1)) break;
                }
                else { window = IntPtr.Zero; stable.Reset(); }
                Thread.Sleep(50);
            }
            Wire.Need(window != IntPtr.Zero && stable.Elapsed >= TimeSpan.FromSeconds(1), 511);
            result.window_observed = true;
            Wire.Need(FindWindow(process.Pid, windowClass) == window && !process.Exited(), 512);
            Wire.Need(Native.SendMessageTimeoutW(window, 0, UIntPtr.Zero, IntPtr.Zero, 3, 1000, out _) != IntPtr.Zero, 513);
            result.window_responsive = true;
            Wire.Need(FindWindow(process.Pid, windowClass) == window && !process.Exited(), 514);
            Wire.Need(Native.PostMessageW(window, 0x0010, UIntPtr.Zero, IntPtr.Zero), 515);
            result.close_sent = true;
            process.WaitExit(TimeSpan.FromSeconds(20));
            result.exit_observed = true; result.exit_code = process.ExitCode();
            string empty = Wire.Hash([]);
            result.stdout_matches = process.Matches(true, empty);
            result.stderr_matches = process.Matches(false, empty);
            Wire.Need(FindWindow(process.Pid, windowClass) == IntPtr.Zero, 516);
            result.passed = result.exit_code == 0 && result.stdout_matches && result.stderr_matches;
        }
        catch (ProbeFailure failure) { result.error = failure.Code; }
        catch (Win32Exception failure) { result.error = failure.NativeErrorCode; }
        catch { result.error = 599; }
        finally { if (process is not null) process.Cleanup(result); }
        result.passed &= result.cleanup_verified && !result.forced_termination && result.error == 0;
        return result;
    }

    private static IntPtr FindWindow(uint processId, string expectedClass)
    {
        IntPtr found = IntPtr.Zero;
        int matching = 0, unexpected = 0;
        Native.EnumWindowsCallback callback = (window, parameter) =>
        {
            _ = Native.GetWindowThreadProcessId(window, out uint owner);
            if (owner != processId || !Native.IsWindowVisible(window)) return true;
            var name = new StringBuilder(256);
            if (Native.GetClassNameW(window, name, name.Capacity) > 0 && name.ToString() == expectedClass && Native.IsWindowEnabled(window))
            { matching++; found = window; }
            else unexpected++;
            return true;
        };
        Wire.Need(Native.EnumWindows(callback, IntPtr.Zero), 517);
        GC.KeepAlive(callback);
        Wire.Need(matching <= 1 && unexpected == 0, 518);
        return matching == 1 ? found : IntPtr.Zero;
    }
}

internal sealed class Capture : IDisposable
{
    private readonly FileStream stream;
    internal Task<byte[]> Work { get; }
    private int overflow, failed;
    internal bool Overflow => Volatile.Read(ref overflow) != 0;
    internal bool Failed => Volatile.Read(ref failed) != 0;
    internal static Capture FromDuplicate(SafeFileHandle source)
    {
        IntPtr current = Native.GetCurrentProcess();
        if (!Native.DuplicateHandle(current, source, current, out var duplicate, 0, false, 2)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return new Capture(duplicate); }
        catch { duplicate.Dispose(); throw; }
    }
    private Capture(SafeFileHandle handle)
    {
        stream = new FileStream(handle, FileAccess.Read, 4096, false);
        Work = Task.Run(() =>
        {
            using var memory = new MemoryStream();
            byte[] buffer = new byte[4096];
            try
            {
                int count;
                while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
                {
                    if (memory.Length + count <= 65536 && !Overflow) memory.Write(buffer, 0, count);
                    else Volatile.Write(ref overflow, 1);
                }
                return memory.ToArray();
            }
            catch { Volatile.Write(ref failed, 1); return []; }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                if (memory.TryGetBuffer(out var segment)) CryptographicOperations.ZeroMemory(segment.AsSpan());
            }
        });
    }
    public void Dispose()
    {
        stream.Dispose();
        if (Work.IsCompletedSuccessfully) CryptographicOperations.ZeroMemory(Work.Result);
    }
}

internal sealed class OwnedProcess
{
    private SafeFileHandle? job, process, thread;
    private Capture? output, error;
    private bool assigned;
    internal uint Pid { get; private set; }
    internal bool OutputOverflow => (output?.Overflow ?? false) || (error?.Overflow ?? false);

    internal static OwnedProcess Create(string file, string argument, bool window, CaseResult evidence)
    {
        var result = new OwnedProcess();
        try { result.Start(file, argument, window, evidence); return result; }
        catch { result.Cleanup(evidence); throw; }
    }

    private void Start(string file, string argument, bool window, CaseResult evidence)
    {
        Native.SetErrorMode(0x0001 | 0x0002 | 0x8000);
        job = Native.CreateJobObjectW(IntPtr.Zero, null);
        RequireHandle(job);
        var limits = new Native.JobExtendedLimit { BasicLimitInformation = new Native.JobBasicLimit { LimitFlags = 0x2000 } };
        if (!Native.SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<Native.JobExtendedLimit>())) throw Win32();
        var security = new Native.SecurityAttributes { nLength = Marshal.SizeOf<Native.SecurityAttributes>(), bInheritHandle = true };
        if (!Native.CreatePipe(out var stdoutRead, out var stdoutWrite, ref security, 0)) throw Win32();
        using (stdoutWrite)
        using (stdoutRead)
        {
            if (!Native.SetHandleInformation(stdoutRead, 1, 0)) throw Win32();
            if (!Native.CreatePipe(out var stderrRead, out var stderrWrite, ref security, 0)) throw Win32();
            using (stderrWrite)
            using (stderrRead)
            using (var input = Native.CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero))
            {
                RequireHandle(input);
                if (!Native.SetHandleInformation(stderrRead, 1, 0)) throw Win32();
                nuint size = 0;
                _ = Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                Wire.Need(size > 0 && size <= 65536, 530);
                IntPtr attributes = Marshal.AllocHGlobal(checked((int)size));
                IntPtr handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
                IntPtr environment = IntPtr.Zero;
                bool initialized = false;
                try
                {
                    if (!Native.InitializeProcThreadAttributeList(attributes, 1, 0, ref size)) throw Win32();
                    initialized = true;
                    Marshal.WriteIntPtr(handles, 0, input.DangerousGetHandle());
                    Marshal.WriteIntPtr(handles, IntPtr.Size, stdoutWrite.DangerousGetHandle());
                    Marshal.WriteIntPtr(handles, IntPtr.Size * 2, stderrWrite.DangerousGetHandle());
                    if (!Native.UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x00020002, handles, (nuint)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero)) throw Win32();
                    var startup = new Native.StartupInfoEx
                    {
                        StartupInfo = new Native.StartupInfo
                        {
                            cb = (uint)Marshal.SizeOf<Native.StartupInfoEx>(), dwFlags = 0x00000100,
                            hStdInput = input.DangerousGetHandle(), hStdOutput = stdoutWrite.DangerousGetHandle(), hStdError = stderrWrite.DangerousGetHandle()
                        },
                        lpAttributeList = attributes
                    };
                    environment = Marshal.StringToHGlobalUni(EnvironmentBlock());
                    string command = "\"" + file + "\"" + (argument.Length == 0 ? "" : " " + argument);
                    uint flags = 0x00000004 | 0x00000400 | 0x00080000 | (window ? 0u : 0x08000000u);
                    if (!Native.CreateProcessW(file, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true, flags, environment, Path.GetDirectoryName(file)!, ref startup, out var info)) throw Win32();
                    process = new SafeFileHandle(info.hProcess, true); thread = new SafeFileHandle(info.hThread, true); Pid = info.dwProcessId;
                    evidence.process_started = true;
                    if (!Native.AssignProcessToJobObject(job, process)) throw Win32();
                    assigned = true;
                    // Duplicate kernel handles: constructor failure can never leave
                    // two independent owning SafeHandle objects for one handle value.
                    output = Capture.FromDuplicate(stdoutRead);
                    error = Capture.FromDuplicate(stderrRead);
                    if (Native.ResumeThread(thread) == uint.MaxValue) throw Win32();
                }
                finally
                {
                    if (initialized) Native.DeleteProcThreadAttributeList(attributes);
                    Marshal.FreeHGlobal(attributes); Marshal.FreeHGlobal(handles);
                    if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                }
            }
        }
    }

    private static string EnvironmentBlock()
    {
        // Explicit benign OS runtime variables only. No GITHUB_TOKEN, Actions service
        // token, OIDC request token, repository credential or receiver key is inherited.
        string[] names = ["SystemRoot", "windir", "SystemDrive", "ComSpec", "PATH", "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "ALLUSERSPROFILE", "USERNAME", "USERDOMAIN", "USERDOMAIN_ROAMINGPROFILE", "HOMEDRIVE", "HOMEPATH", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "PATHEXT", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432", "SESSIONNAME", "OS"];
        var values = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string name in names)
        {
            string? value = Environment.GetEnvironmentVariable(name);
            if (value is not null && !value.Contains('\0')) values[name] = value;
        }
        return string.Join('\0', values.Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
    }
    private static Win32Exception Win32() => new(Marshal.GetLastWin32Error());
    private static void RequireHandle(SafeFileHandle handle) { if (handle.IsInvalid) throw Win32(); }
    internal bool Exited()
    {
        Wire.Need(process is not null && !process.IsInvalid, 531);
        uint status = Native.WaitForSingleObject(process!, 0);
        Wire.Need(status is 0 or 258, 532);
        return status == 0;
    }
    internal void WaitExit(TimeSpan limit)
    {
        var timer = Stopwatch.StartNew();
        while (!Exited() && timer.Elapsed < limit)
        {
            Wire.Need(!OutputOverflow, 533);
            Thread.Sleep(20);
        }
        Wire.Need(Exited(), 534);
        Wire.Need(output is not null && error is not null && Task.WaitAll([output.Work, error.Work], 2000), 535);
        Wire.Need(!OutputOverflow && !output!.Failed && !error!.Failed, 536);
    }
    internal uint ExitCode()
    {
        Wire.Need(Exited(), 537);
        if (!Native.GetExitCodeProcess(process!, out uint code)) throw Win32();
        return code;
    }
    internal bool Matches(bool stdout, string expected)
    {
        var capture = stdout ? output : error;
        Wire.Need(capture is not null && capture.Work.IsCompletedSuccessfully && !capture.Failed && !capture.Overflow, 538);
        byte[] normalized = Wire.NormalizeOutput(capture!.Work.Result);
        try { return Wire.Hash(normalized) == expected; }
        finally { CryptographicOperations.ZeroMemory(normalized); }
    }
    private bool JobEmpty()
    {
        if (job is null || job.IsInvalid) return process is null;
        return Native.QueryInformationJobObject(job, 1, out var accounting, (uint)Marshal.SizeOf<Native.JobAccounting>(), IntPtr.Zero) && accounting.ActiveProcesses == 0;
    }
    internal void Cleanup(CaseResult result)
    {
        bool stopped = process is null, closed = false;
        try
        {
            if (process is not null && !process.IsInvalid)
            {
                stopped = Native.WaitForSingleObject(process, 0) == 0;
                if (!stopped || !JobEmpty())
                {
                    result.forced_termination = true;
                    bool terminated = assigned && job is not null ? Native.TerminateJobObject(job, 0xdead) : Native.TerminateProcess(process, 0xdead);
                    stopped = terminated && Native.WaitForSingleObject(process, 2000) == 0;
                }
            }
            var deadline = Stopwatch.StartNew();
            while (!JobEmpty() && deadline.Elapsed < TimeSpan.FromSeconds(2)) Thread.Sleep(20);
            result.job_empty = JobEmpty();
            bool captureComplete = (output is null || output.Work.Wait(2000)) && (error is null || error.Work.Wait(2000));
            closed = captureComplete;
        }
        catch { closed = false; }
        finally
        {
            try { output?.Dispose(); } catch { closed = false; }
            try { error?.Dispose(); } catch { closed = false; }
            try { thread?.Dispose(); } catch { closed = false; }
            try { process?.Dispose(); } catch { closed = false; }
            try { job?.Dispose(); } catch { closed = false; }
        }
        result.cleanup_verified = stopped && result.job_empty && closed;
    }
}

internal static class Native
{
    [StructLayout(LayoutKind.Sequential)] internal struct SecurityAttributes { internal int nLength; internal IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] internal bool bInheritHandle; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] internal struct StartupInfo
    {
        internal uint cb; internal IntPtr lpReserved, lpDesktop, lpTitle;
        internal uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        internal ushort wShowWindow, cbReserved2; internal IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)] internal struct StartupInfoEx { internal StartupInfo StartupInfo; internal IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)] internal struct ProcessInformation { internal IntPtr hProcess, hThread; internal uint dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] internal struct JobBasicLimit { internal long PerProcessUserTimeLimit, PerJobUserTimeLimit; internal uint LimitFlags; internal nuint MinimumWorkingSetSize, MaximumWorkingSetSize; internal uint ActiveProcessLimit; internal nuint Affinity; internal uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] internal struct IoCounters { internal ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] internal struct JobExtendedLimit { internal JobBasicLimit BasicLimitInformation; internal IoCounters IoInfo; internal nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [StructLayout(LayoutKind.Sequential)] internal struct JobAccounting { internal long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime; internal uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses; }
    [StructLayout(LayoutKind.Sequential)] internal struct UserObjectFlags { internal int fInherit, fReserved; internal uint dwFlags; }
    internal delegate bool EnumWindowsCallback(IntPtr window, IntPtr parameter);
    [DllImport("kernel32.dll")] internal static extern uint SetErrorMode(uint mode);
    [DllImport("kernel32.dll")] internal static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll")] internal static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool DuplicateHandle(IntPtr sourceProcess, SafeFileHandle source, IntPtr targetProcess, out SafeFileHandle target, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool WTSQuerySessionInformationW(IntPtr server, uint session, int infoClass, out IntPtr buffer, out uint count);
    [DllImport("wtsapi32.dll")] internal static extern void WTSFreeMemory(IntPtr buffer);
    [DllImport("user32.dll")] internal static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetUserObjectInformationW(IntPtr handle, int index, out UserObjectFlags info, uint length, out uint needed);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JobExtendedLimit info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryInformationJobObject(SafeFileHandle job, int infoClass, out JobAccounting info, uint length, IntPtr returned);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool TerminateJobObject(SafeFileHandle job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool TerminateProcess(SafeFileHandle process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool GetExitCodeProcess(SafeFileHandle process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] internal static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes attributes, uint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern SafeFileHandle CreateFileW(string name, uint access, uint share, ref SecurityAttributes security, uint creation, uint attributes, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, nuint size, IntPtr previous, IntPtr returned);
    [DllImport("kernel32.dll")] internal static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processSecurity, IntPtr threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfoEx startup, out ProcessInformation info);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr parameter);
    [DllImport("user32.dll")] internal static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] internal static extern int GetClassNameW(IntPtr window, StringBuilder className, int count);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] internal static extern IntPtr SendMessageTimeoutW(IntPtr window, uint message, UIntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool PostMessageW(IntPtr window, uint message, UIntPtr wparam, IntPtr lparam);
}
