using System.Runtime.InteropServices;
using System.Text.Json;

namespace SessionContractExperiment;

// A compact report shared only by the two processes owned by this experiment.
// It never contains the expected keyboard challenge; only the child's actual
// messages can populate ReceivedHex. No process/window handles are serialized.
internal sealed class InputObservation
{
    public InputObservation() { }
    public string Schema { get; set; } = "witness-input/v1";
    public long Sequence { get; set; }
    public string Nonce { get; set; } = "";
    public uint SessionId { get; set; }
    public string IdentityDigest { get; set; } = "";
    public bool Shown { get; set; }
    public bool Closed { get; set; }
    public bool WindowVisible { get; set; }
    public bool ForegroundOwn { get; set; }
    public bool FocusOwn { get; set; }
    public bool DesktopInputQuerySucceeded { get; set; }
    public bool DesktopReceivesInput { get; set; }
    public int DesktopQueryError { get; set; }
    public int MonitorCount { get; set; }
    public InputRectangle VirtualScreen { get; set; }
    public InputRectangle ClientScreen { get; set; }
    public InputRectangle PhysicalClientScreen { get; set; }
    public bool PhysicalEqualsLogical { get; set; }
    public bool CursorQuerySucceeded { get; set; }
    public InputPoint Cursor { get; set; }
    public int CursorError { get; set; }
    public long MessageSequence { get; set; }
    public int MoveCount { get; set; }
    public long MoveSequence { get; set; }
    public InputPoint? MovePoint { get; set; }
    public bool MoveHitOwnRoot { get; set; }
    public int LeftDownCount { get; set; }
    public int LeftUpCount { get; set; }
    public long LeftDownSequence { get; set; }
    public long LeftUpSequence { get; set; }
    public InputPoint? LeftDownPoint { get; set; }
    public InputPoint? LeftUpPoint { get; set; }
    public int UnexpectedButtons { get; set; }
    public int KeyDownCount { get; set; }
    public int KeyUpCount { get; set; }
    public int CharacterCount { get; set; }
    public int CharacterLimit { get; set; } = 8;
    public int UnexpectedCharacters { get; set; }
    public int RepeatedCharacters { get; set; }
    public int OverflowCharacters { get; set; }
    public int SystemCharacters { get; set; }
    public string ReceivedHex { get; set; } = "";
    public string? FailureStage { get; set; }
    public int FailureHresult { get; set; }
}

internal readonly record struct InputPoint(int X, int Y);
internal readonly record struct InputRectangle(int X, int Y, int Width, int Height)
{
    internal static InputRectangle From(Rectangle value) => new(value.X, value.Y, value.Width, value.Height);
    internal Rectangle Rectangle => new(X, Y, Width, Height);
}

internal static class InputReport
{
    internal static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    internal static InputObservation Read(string path, string nonce, uint session, string digest)
    {
        using FileStream file = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (file.Length is <= 0 or > 65536) throw new ExperimentFailure("input_report_size_invalid");
        InputObservation observation = JsonSerializer.Deserialize<InputObservation>(file, Options) ??
            throw new ExperimentFailure("input_report_empty");
        if (observation.Schema != "witness-input/v1" || observation.Nonce != nonce ||
            observation.SessionId != session || observation.IdentityDigest != digest || observation.Sequence <= 0)
            throw new ExperimentFailure("input_report_binding_invalid");
        if (observation.CharacterLimit is not 8 and not 16 || observation.ReceivedHex.Length > observation.CharacterLimit ||
            observation.ReceivedHex.Any(c => !IsAsciiHex(c)))
            throw new ExperimentFailure("input_report_character_format_invalid");
        return observation;
    }

    internal static bool IsAsciiHex(char value) => value is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f';
}

internal static class InputNative
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Point
    {
        internal int X, Y;
        internal Point(int x, int y) { X = x; Y = y; }
        internal InputPoint Value => new(X, Y);
    }

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetCursorPos(out Point point);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ClientToScreen(IntPtr window, ref Point point);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LogicalToPhysicalPointForPerMonitorDPI(IntPtr window, ref Point point);
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetAncestor(IntPtr window, uint flags);
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetFocus();
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern IntPtr WindowFromPoint(Point point);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsChild(IntPtr parent, IntPtr child);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetThreadDesktop(uint thread);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DesktopInput(IntPtr desktop, int index, out int receivesInput, uint length, out uint needed);

    internal static bool OwnRoot(IntPtr window, IntPtr other)
    {
        IntPtr root = GetAncestor(window, 2);
        return root != IntPtr.Zero && other != IntPtr.Zero && GetAncestor(other, 2) == root;
    }

    internal static bool KeyboardMessage(int id) => id is >= 0x0100 and <= 0x0109;
    internal static bool ButtonMessage(int id) => id is >= 0x0201 and <= 0x020E or >= 0x00A1 and <= 0x00AD;
}
