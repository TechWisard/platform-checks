using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace SessionContractExperiment;

// Read-only, bounded observations. Native identifiers and full image paths
// stay internal. An otherwise unclassified, stable same-session owner may
// expose only a short validated process basename and window class name.
internal static class WindowCoverageDiagnostics
{
    private const int MaximumProcessBaseNameLength = 128;
    private const int MaximumWindowClassNameLength = 256;
    private const int MaximumApplicationIdentityLength = 256;

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
        bool mayIdentifyOther = !isOwn && currentSessionOkay && sessionOkay && session == currentSession;
        (string classCategory, bool classOkay, int classError, string? otherClassName) =
            ReadClass(window, isOwn, mayIdentifyOther);
        ProcessObservation processObservation = isOwn ? new("own", null, 0, null, null) :
            ReadProcessCategory(process, mayIdentifyOther);
        (string processCategory, bool? imageOkay, int imageError, string? otherProcessBaseName, _) = processObservation;
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
            OtherProcessBaseName = stable && mayIdentifyOther && imageOkay == true && processCategory == "other" ?
                otherProcessBaseName : null,
            HostApplicationIdentity = stable && mayIdentifyOther ? processObservation.HostIdentity : null,
            ClassCategory = stable ? classCategory : "unavailable",
            ClassQuerySucceeded = classOkay,
            ClassQueryWin32Error = classError,
            OtherWindowClassName = stable && mayIdentifyOther && classOkay && classCategory == "other" ?
                otherClassName : null,
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

    private static (string Category, bool Succeeded, int Error, string? OtherName)
        ReadClass(IntPtr window, bool ownProcess, bool mayIdentifyOther)
    {
        // Two extra characters distinguish an accepted maximum-length name
        // from a buffer-filling result that might have been truncated.
        char[] buffer = new char[MaximumWindowClassNameLength + 2];
        try
        {
            int length = GetClassNameW(window, buffer, buffer.Length);
            if (length == 0) return ("unavailable", false, Marshal.GetLastWin32Error(), null);
            if (length < 0 || length > MaximumWindowClassNameLength) return ("unavailable", false, 122, null);
            ReadOnlySpan<char> name = buffer.AsSpan(0, length);
            if (ownProcess) return ("own", true, 0, null);
            string category = name.Equals("ConsoleWindowClass", StringComparison.OrdinalIgnoreCase) ? "conhost" :
                name.Equals("CASCADIA_HOSTING_WINDOW_CLASS", StringComparison.OrdinalIgnoreCase) ? "windows-terminal" :
                name.Equals("Shell_TrayWnd", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Shell_SecondaryTrayWnd", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Progman", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("WorkerW", StringComparison.OrdinalIgnoreCase) ? "shell" : "other";
            string? otherName = category == "other" && mayIdentifyOther ?
                SafeShortName(name, MaximumWindowClassNameLength, windowClass: true) : null;
            return (category, true, 0, otherName);
        }
        finally { Array.Clear(buffer); }
    }

    private static ProcessObservation
        ReadProcessCategory(uint process, bool mayIdentifyOther)
    {
        using SafeProcessHandle handle = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, process);
        if (handle.IsInvalid) return new("unavailable", false, Marshal.GetLastWin32Error(), null, null);
        char[] buffer = new char[1024];
        try
        {
            uint length = checked((uint)buffer.Length);
            if (!QueryFullProcessImageNameW(handle, 0, buffer, ref length))
                return new("unavailable", false, Marshal.GetLastWin32Error(), null, null);
            if (length == 0 || length >= buffer.Length) return new("unavailable", false, 13, null, null);
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
            string? otherName = category == "other" && mayIdentifyOther ?
                SafeShortName(name, MaximumProcessBaseNameLength, windowClass: false) : null;
            // WWAHost is only a generic application host. Query its documented
            // package identity on this same limited-information handle; never
            // inspect command lines, window text, URLs, or another process.
            HostApplicationIdentity? hostIdentity = mayIdentifyOther &&
                name.Equals("WWAHost.exe", StringComparison.OrdinalIgnoreCase) ? ReadHostIdentity(handle) : null;
            return new(category, true, 0, otherName, hostIdentity);
        }
        finally { Array.Clear(buffer); }
    }

    private static HostApplicationIdentity ReadHostIdentity(SafeProcessHandle process)
    {
        char[] family = new char[MaximumApplicationIdentityLength + 1];
        char[] application = new char[MaximumApplicationIdentityLength + 1];
        try
        {
            uint familyLength = checked((uint)family.Length);
            uint applicationLength = checked((uint)application.Length);
            int familyResult = GetPackageFamilyName(process, ref familyLength, family);
            int applicationResult = GetApplicationUserModelId(process, ref applicationLength, application);
            return new(familyResult, ReadApplicationIdentity(family, familyLength, familyResult),
                applicationResult, ReadApplicationIdentity(application, applicationLength, applicationResult));
        }
        finally { Array.Clear(family); Array.Clear(application); }
    }

    private static string? ReadApplicationIdentity(char[] buffer, uint length, int result)
    {
        // Both APIs return a status directly and count the terminating NUL.
        if (result != 0 || length < 2 || length > buffer.Length || buffer[length - 1] != '\0') return null;
        ReadOnlySpan<char> value = buffer.AsSpan(0, checked((int)length - 1));
        foreach (char character in value)
            if (!(character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-' or '!'))
                return null;
        return new string(value);
    }

    private static string? SafeShortName(ReadOnlySpan<char> name, int maximumLength, bool windowClass)
    {
        if (name.IsEmpty || name.Length > maximumLength) return null;
        foreach (char value in name)
        {
            bool permitted = value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or
                '.' or '_' or '-' or ' ' or '(' or ')';
            if (windowClass && (value is '#' or ':' or ';' or '[' or ']' or '{' or '}')) permitted = true;
            if (!permitted) return null;
        }
        // Never sanitize or truncate into a misleading different identifier.
        return new string(name);
    }

    private readonly record struct NativeStyle(bool Succeeded, uint? Value, bool? TopMost, int Error);
    private sealed record ProcessObservation(string Category, bool? Succeeded, int Error,
        string? OtherName, HostApplicationIdentity? HostIdentity);
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
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int GetPackageFamilyName(SafeProcessHandle process, ref uint length, [Out] char[] familyName);
    [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int GetApplicationUserModelId(SafeProcessHandle process, ref uint length, [Out] char[] applicationId);
}

internal sealed record HostApplicationIdentity(int PackageFamilyQueryResult, string? PackageFamilyName,
    int ApplicationIdQueryResult, string? ApplicationUserModelId);

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
    public string? OtherProcessBaseName { get; init; }
    public HostApplicationIdentity? HostApplicationIdentity { get; init; }
    public string ClassCategory { get; init; } = "unavailable";
    public bool ClassQuerySucceeded { get; init; }
    public int ClassQueryWin32Error { get; init; }
    public string? OtherWindowClassName { get; init; }
    public bool ExtendedStyleQuerySucceeded { get; init; }
    public bool? ActualTopMost { get; init; }
    public int ExtendedStyleQueryWin32Error { get; init; }
    public bool OwnerRecheckSucceeded { get; init; }
    public bool? OwnerUnchanged { get; init; }
    public int OwnerRecheckWin32Error { get; init; }
}
