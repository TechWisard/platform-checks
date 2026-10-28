using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace SessionContractExperiment;

// Read-only, bounded observations. Native identifiers and raw image/class
// names stay inside this method; the returned records contain only categories,
// equality booleans, own geometry/styles, and numeric query results.
internal static class WindowCoverageDiagnostics
{
    internal static WindowCoverageDiagnosticSnapshot Capture(Form form, IntPtr ownRoot,
        IntPtr foregroundRoot, IntPtr[] hitRoots)
    {
        try
        {
            uint ownProcess = GetCurrentProcessId();
            bool currentSessionOkay = ProcessIdToSessionId(ownProcess, out uint currentSession);
            int currentSessionError = currentSessionOkay ? 0 : Marshal.GetLastWin32Error();
            Dictionary<IntPtr, WindowRootOwnership> cache = new();
            WindowRootOwnership Read(IntPtr window)
            {
                if (!cache.TryGetValue(window, out WindowRootOwnership? result))
                {
                    result = ReadRoot(window, ownProcess, currentSessionOkay, currentSession);
                    cache.Add(window, result);
                }
                return result;
            }
            return new(ReadOwnWindow(form, ownRoot), currentSessionOkay, currentSessionError,
                Read(ownRoot), Read(foregroundRoot), hitRoots.Select(Read).ToArray(), 0);
        }
        catch (Exception exception)
        {
            // Diagnostic failure never changes frame acceptance or presentation.
            return new(null, false, 0, null, null, Array.Empty<WindowRootOwnership>(), exception.HResult);
        }
    }

    private static OwnNativeWindowState ReadOwnWindow(Form form, IntPtr ownRoot)
    {
        IntPtr window = form.Handle;
        NativeStyle style = ReadStyle(window);
        bool affinityOkay = GetWindowDisplayAffinity(window, out uint affinity);
        int affinityError = affinityOkay ? 0 : Marshal.GetLastWin32Error();
        bool rectOkay = GetWindowRect(window, out NativeRectangle rectangle);
        int rectError = rectOkay ? 0 : Marshal.GetLastWin32Error();
        FrameRectangle? bounds = rectOkay ? new(rectangle.Left, rectangle.Top,
            checked(rectangle.Right - rectangle.Left), checked(rectangle.Bottom - rectangle.Top)) : null;
        return new(style.Succeeded, style.Value, style.TopMost, style.Error,
            affinityOkay, affinityOkay ? affinity : null, affinityError,
            rectOkay, bounds, rectOkay ? bounds == FrameRectangle.From(form.Bounds) : null, rectError,
            ownRoot != IntPtr.Zero ? ownRoot == window : null);
    }

    private static WindowRootOwnership ReadRoot(IntPtr window, uint ownProcess, bool currentSessionOkay, uint currentSession)
    {
        if (window == IntPtr.Zero) return new();
        uint process = 0;
        uint thread = GetWindowThreadProcessId(window, ref process);
        int ownerError = thread != 0 ? 0 : Marshal.GetLastWin32Error();
        if (thread == 0 || process == 0)
            return new() { WindowPresent = true, OwnerQueryWin32Error = ownerError };

        bool isOwn = process == ownProcess;
        bool sessionOkay = ProcessIdToSessionId(process, out uint session);
        int sessionError = sessionOkay ? 0 : Marshal.GetLastWin32Error();
        (string classCategory, bool classOkay, int classError) = ReadClass(window, isOwn);
        (string processCategory, bool? imageOkay, int imageError) = isOwn ?
            ("own", null, 0) : ReadProcessCategory(process);
        NativeStyle style = ReadStyle(window);

        // HWND/process lifetime can change during any read-only snapshot.
        // If the owner changed, do not attribute stale categories to this root.
        uint recheckProcess = 0;
        uint recheckThread = GetWindowThreadProcessId(window, ref recheckProcess);
        int recheckError = recheckThread != 0 ? 0 : Marshal.GetLastWin32Error();
        bool stable = recheckThread != 0 && recheckProcess == process && recheckThread == thread;
        return new()
        {
            WindowPresent = true,
            OwnerQuerySucceeded = true,
            OwnerQueryWin32Error = 0,
            OwnProcess = stable ? isOwn : null,
            SessionQuerySucceeded = sessionOkay,
            SessionQueryWin32Error = sessionError,
            SameSession = stable && currentSessionOkay && sessionOkay ? session == currentSession : null,
            ProcessCategory = stable ? processCategory : "unavailable",
            ProcessImageQuerySucceeded = imageOkay,
            ProcessImageQueryWin32Error = imageError,
            ClassCategory = stable ? classCategory : "unavailable",
            ClassQuerySucceeded = classOkay,
            ClassQueryWin32Error = classError,
            ExtendedStyleQuerySucceeded = style.Succeeded,
            ActualTopMost = stable ? style.TopMost : null,
            ExtendedStyleQueryWin32Error = style.Error,
            OwnerRecheckSucceeded = recheckThread != 0,
            OwnerUnchanged = stable,
            OwnerRecheckWin32Error = recheckError
        };
    }

    private static NativeStyle ReadStyle(IntPtr window)
    {
        SetLastError(0);
        IntPtr value = IntPtr.Size == 8 ? GetWindowLongPtrW(window, -20 /* GWL_EXSTYLE */) :
            new IntPtr(GetWindowLongW(window, -20));
        int error = Marshal.GetLastWin32Error();
        bool succeeded = value != IntPtr.Zero || error == 0;
        uint? style = succeeded ? unchecked((uint)value.ToInt64()) : null;
        return new(succeeded, style, style.HasValue ? (style.Value & 0x00000008 /* WS_EX_TOPMOST */) != 0 : null,
            succeeded ? 0 : error);
    }

    private static (string Category, bool Succeeded, int Error) ReadClass(IntPtr window, bool ownProcess)
    {
        char[] buffer = new char[256];
        try
        {
            int length = GetClassNameW(window, buffer, buffer.Length);
            if (length == 0) return ("unavailable", false, Marshal.GetLastWin32Error());
            if (length < 0 || length >= buffer.Length - 1) return ("unavailable", false, 122);
            ReadOnlySpan<char> name = buffer.AsSpan(0, length);
            if (ownProcess) return ("own", true, 0);
            string category = name.Equals("ConsoleWindowClass", StringComparison.OrdinalIgnoreCase) ? "conhost" :
                name.Equals("CASCADIA_HOSTING_WINDOW_CLASS", StringComparison.OrdinalIgnoreCase) ? "windows-terminal" :
                name.Equals("Shell_TrayWnd", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Shell_SecondaryTrayWnd", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Progman", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("WorkerW", StringComparison.OrdinalIgnoreCase) ? "shell" : "other";
            return (category, true, 0);
        }
        finally { Array.Clear(buffer); }
    }

    private static (string Category, bool? Succeeded, int Error) ReadProcessCategory(uint process)
    {
        using SafeProcessHandle handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, process);
        if (handle.IsInvalid) return ("unavailable", false, Marshal.GetLastWin32Error());
        char[] buffer = new char[1024];
        try
        {
            uint length = checked((uint)buffer.Length);
            if (!QueryFullProcessImageNameW(handle, 0, buffer, ref length))
                return ("unavailable", false, Marshal.GetLastWin32Error());
            if (length == 0 || length >= buffer.Length) return ("unavailable", false, 13);
            ReadOnlySpan<char> image = buffer.AsSpan(0, checked((int)length));
            int separator = Math.Max(image.LastIndexOf('\\'), image.LastIndexOf('/'));
            ReadOnlySpan<char> name = image[(separator + 1)..];
            string category = name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) ? "explorer" :
                name.Equals("firstlogonanim.exe", StringComparison.OrdinalIgnoreCase) ? "firstlogonanim" :
                name.Equals("logonui.exe", StringComparison.OrdinalIgnoreCase) ? "logonui" :
                name.Equals("conhost.exe", StringComparison.OrdinalIgnoreCase) ? "conhost" :
                name.Equals("openconsole.exe", StringComparison.OrdinalIgnoreCase) ? "openconsole" :
                name.Equals("windowsterminal.exe", StringComparison.OrdinalIgnoreCase) ? "windows-terminal" :
                name.Equals("shellexperiencehost.exe", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("startmenuexperiencehost.exe", StringComparison.OrdinalIgnoreCase) ? "shell" : "other";
            return (category, true, 0);
        }
        finally { Array.Clear(buffer); }
    }

    private readonly record struct NativeStyle(bool Succeeded, uint? Value, bool? TopMost, int Error);
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRectangle { internal int Left, Top, Right, Bottom; }
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr window, ref uint processId);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetWindowLongPtrW(IntPtr window, int index);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int GetWindowLongW(IntPtr window, int index);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern void SetLastError(uint error);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowDisplayAffinity(IntPtr window, out uint affinity);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr window, out NativeRectangle rectangle);
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetClassNameW(IntPtr window, [Out] char[] className, int capacity);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags,
        [Out] char[] imageName, ref uint length);
}

internal sealed record WindowCoverageDiagnosticSnapshot(OwnNativeWindowState? OwnWindow,
    bool CurrentProcessSessionQuerySucceeded, int CurrentProcessSessionQueryWin32Error,
    WindowRootOwnership? OwnRoot, WindowRootOwnership? ForegroundRoot, WindowRootOwnership[] HitRoots,
    int DiagnosticHresult);

internal sealed record OwnNativeWindowState(bool ExtendedStyleQuerySucceeded, uint? ExtendedStyle,
    bool? ActualTopMost, int ExtendedStyleQueryWin32Error,
    bool DisplayAffinityQuerySucceeded, uint? DisplayAffinity, int DisplayAffinityQueryWin32Error,
    bool WindowRectQuerySucceeded, FrameRectangle? WindowRect, bool? WindowRectMatchesFormBounds,
    int WindowRectQueryWin32Error, bool? OwnRootIsFormWindow);

internal sealed record WindowRootOwnership
{
    public bool WindowPresent { get; init; }
    public bool OwnerQuerySucceeded { get; init; }
    public int OwnerQueryWin32Error { get; init; }
    public bool? OwnProcess { get; init; }
    public bool SessionQuerySucceeded { get; init; }
    public int SessionQueryWin32Error { get; init; }
    public bool? SameSession { get; init; }
    public string ProcessCategory { get; init; } = "unavailable";
    public bool? ProcessImageQuerySucceeded { get; init; }
    public int ProcessImageQueryWin32Error { get; init; }
    public string ClassCategory { get; init; } = "unavailable";
    public bool ClassQuerySucceeded { get; init; }
    public int ClassQueryWin32Error { get; init; }
    public bool ExtendedStyleQuerySucceeded { get; init; }
    public bool? ActualTopMost { get; init; }
    public int ExtendedStyleQueryWin32Error { get; init; }
    public bool OwnerRecheckSucceeded { get; init; }
    public bool? OwnerUnchanged { get; init; }
    public int OwnerRecheckWin32Error { get; init; }
}
