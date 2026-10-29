using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace RuntimeProbe;

// A receiver spans workflow steps. Inheriting the launching step's pipe handles
// would keep those streams open and cause the runner to terminate its process
// tree after its stream grace period. Only the three explicit NUL handles below
// are inherited; ordinary runner process tracking and job membership remain.
internal static class ReceiverLauncher
{
    internal static int Run(string requestedRoot, string requestNonce)
    {
        SafeFileHandle? process = null, thread = null;
        IntPtr rawProcess = IntPtr.Zero, rawThread = IntPtr.Zero;
        bool launched = false, started = false, stopped = false;
        string phase = "context";
        try
        {
            Wire.Need(OperatingSystem.IsWindows() && Environment.Is64BitProcess && Wire.Hex(requestNonce, 64), 600);
            string root = Path.GetFullPath(requestedRoot);
            string prefix = Path.GetFullPath(Program.Env("RUNNER_TEMP")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string name = Path.GetFileName(root);
            Wire.Need(root.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && name.StartsWith("runtime-probe-", StringComparison.Ordinal) && Wire.Hex(name[14..], 32), 601);
            Wire.Need(Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0, 602);
            string runtime = Environment.ProcessPath ?? "";
            string assembly = typeof(ReceiverLauncher).Assembly.Location;
            Wire.Need(Path.GetFileName(runtime).Equals("dotnet.exe", StringComparison.OrdinalIgnoreCase) && Path.GetFileName(assembly) == "RuntimeProbe.dll", 603);
            string command = Quote(runtime) + " " + Quote(assembly) + " --receive " + Quote(root) + " " + requestNonce;
            Wire.Need(command.Length < 8192, 604);
            phase = "handles";
            var security = new Native.SecurityAttributes { nLength = Marshal.SizeOf<Native.SecurityAttributes>(), bInheritHandle = true };
            using var input = Native.CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero);
            using var output = Native.CreateFileW("NUL", 0x40000000, 3, ref security, 3, 0, IntPtr.Zero);
            using var error = Native.CreateFileW("NUL", 0x40000000, 3, ref security, 3, 0, IntPtr.Zero);
            Wire.Need(!input.IsInvalid && !output.IsInvalid && !error.IsInvalid, 605);
            nuint size = 0;
            _ = Native.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            Wire.Need(size > 0 && size <= 65536, 606);
            IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero;
            bool initialized = false;
            try
            {
                attributes = Marshal.AllocHGlobal(checked((int)size));
                handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
                phase = "attributes";
                Wire.Need(Native.InitializeProcThreadAttributeList(attributes, 1, 0, ref size), 607);
                initialized = true;
                Marshal.WriteIntPtr(handles, 0, input.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size, output.DangerousGetHandle());
                Marshal.WriteIntPtr(handles, IntPtr.Size * 2, error.DangerousGetHandle());
                Wire.Need(Native.UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x00020002, handles, (nuint)(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero), 608);
                var startup = new Native.StartupInfoEx
                {
                    StartupInfo = new Native.StartupInfo
                    {
                        cb = (uint)Marshal.SizeOf<Native.StartupInfoEx>(), dwFlags = 0x00000100,
                        hStdInput = input.DangerousGetHandle(), hStdOutput = output.DangerousGetHandle(), hStdError = error.DangerousGetHandle()
                    },
                    lpAttributeList = attributes
                };
                // CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
                // EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW.
                // No BREAKAWAY flag, altered runner tracking, or launcher-owned
                // kill-on-close job: the normal workflow cleanup still owns us.
                phase = "create";
                Wire.Need(Native.CreateProcessW(runtime, new StringBuilder(command), IntPtr.Zero, IntPtr.Zero, true,
                    0x08080404, IntPtr.Zero, Path.GetDirectoryName(assembly)!, ref startup, out var info), 609);
                started = true;
                rawProcess = info.hProcess; rawThread = info.hThread;
                process = new SafeFileHandle(rawProcess, true); rawProcess = IntPtr.Zero;
                thread = new SafeFileHandle(rawThread, true); rawThread = IntPtr.Zero;
                phase = "receipt";
                Wire.Need(GetProcessTimes(process, out long created, out _, out _, out _), 610);
                long startUtcTicks = DateTime.FromFileTimeUtc(created).Ticks;
                byte[] receipt = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schema = "runtime-process/v1", pid = info.dwProcessId, startUtcTicks, executable = runtime
                });
                string pending = Path.Combine(root, "process.pending");
                using (var file = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None)) file.Write(receipt);
                File.Move(pending, Path.Combine(root, "process.json"), false);
                phase = "resume";
                Wire.Need(Native.ResumeThread(thread) != uint.MaxValue, 611);
                launched = true;
                phase = "complete";
            }
            finally
            {
                if (initialized) Native.DeleteProcThreadAttributeList(attributes);
                if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
            }
        }
        catch
        {
            // A failed launch can terminate only the handle created above.
            // The receipt, if committed, lets Wait-Probe verify its identity.
            if (process is not null && !process.IsInvalid)
            {
                stopped = Native.WaitForSingleObject(process, 0) == 0;
                if (!stopped) stopped = Native.TerminateProcess(process, 0xdead) && Native.WaitForSingleObject(process, 5000) == 0;
            }
            else if (rawProcess != IntPtr.Zero && rawProcess != new IntPtr(-1))
            {
                stopped = WaitForSingleObject(rawProcess, 0) == 0;
                if (!stopped) stopped = TerminateProcess(rawProcess, 0xdead) && WaitForSingleObject(rawProcess, 5000) == 0;
            }
            else stopped = !started;
        }
        finally
        {
            thread?.Dispose(); process?.Dispose();
            if (rawThread != IntPtr.Zero && rawThread != new IntPtr(-1)) _ = CloseHandle(rawThread);
            if (rawProcess != IntPtr.Zero && rawProcess != new IntPtr(-1)) _ = CloseHandle(rawProcess);
        }
        Console.WriteLine(JsonSerializer.Serialize(new { schema = "runtime-launch/v1", phase, launched, process_started = started, receiver_stopped = stopped }));
        return launched ? 0 : 1;
    }

    private static string Quote(string value)
    {
        Wire.Need(value.Length is > 0 and <= 2048 && !value.Any(character => character < 32 || character == '"') && !value.EndsWith('\\'), 612);
        return "\"" + value + "\"";
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeFileHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr process, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
