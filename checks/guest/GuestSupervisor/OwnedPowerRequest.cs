using System.Runtime.InteropServices;

namespace SessionContractExperiment;

// One temporary request belonging only to this disposable GUI fixture.
// It does not change a power plan, registry policy, or user-initiated sleep.
// The caller must invoke Release in its common finally and inspect Evidence.
internal sealed class OwnedPowerRequest : IDisposable
{
    internal sealed class Observation
    {
        public bool AcquisitionAttempted { get; internal set; }
        public int ContextBytes { get; internal set; }
        public bool Created { get; internal set; }
        public bool SystemRequiredSet { get; internal set; }
        public bool DisplayRequiredSet { get; internal set; }
        public uint? CreateWin32Error { get; internal set; }
        public uint? SetSystemWin32Error { get; internal set; }
        public uint? SetDisplayWin32Error { get; internal set; }
        public bool Acquired => Created && SystemRequiredSet && DisplayRequiredSet;
        public bool ReleaseAttempted { get; internal set; }
        public bool SystemRequiredCleared { get; internal set; }
        public bool DisplayRequiredCleared { get; internal set; }
        public uint? ClearSystemWin32Error { get; internal set; }
        public uint? ClearDisplayWin32Error { get; internal set; }
        public bool HandleClosed { get; internal set; }
        public uint? CloseWin32Error { get; internal set; }
        public uint? ReleaseExceptionHresult { get; internal set; }
        public bool ReasonBufferReleased { get; internal set; } = true;
        public bool CleanupVerified => ReleaseAttempted && ReleaseExceptionHresult is null &&
            (!Created || HandleClosed) && (!SystemRequiredSet || SystemRequiredCleared) &&
            (!DisplayRequiredSet || DisplayRequiredCleared) && ReasonBufferReleased;
    }

    // x64: eight header bytes plus the full 24-byte Detailed/Simple union.
    // This fixture deliberately rejects other process widths before the call.
    [StructLayout(LayoutKind.Explicit, Size = 32)]
    private struct ReasonContext64
    {
        [FieldOffset(0)] internal uint Version;
        [FieldOffset(4)] internal uint Flags;
        [FieldOffset(8)] internal IntPtr SimpleReasonString;
    }

    private enum RequestType { DisplayRequired = 0, SystemRequired = 1 }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr PowerCreateRequest(ref ReasonContext64 context);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PowerSetRequest(IntPtr request, RequestType type);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PowerClearRequest(IntPtr request, RequestType type);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private IntPtr request;
    private IntPtr reason;
    private bool released;
    internal Observation Evidence { get; } = new();

    internal void Acquire()
    {
        if (Evidence.AcquisitionAttempted || released)
            throw new InvalidOperationException("power_request_one_use_required");
        Evidence.AcquisitionAttempted = true;
        Evidence.ContextBytes = Marshal.SizeOf<ReasonContext64>();
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8 || Evidence.ContextBytes != 32)
            throw new PlatformNotSupportedException("power_request_windows_64_required");

        reason = Marshal.StringToHGlobalUni("Owned disposable Windows GUI test");
        Evidence.ReasonBufferReleased = false;
        ReasonContext64 context = new() { Version = 0, Flags = 1, SimpleReasonString = reason };
        request = PowerCreateRequest(ref context);
        if (request == IntPtr.Zero || request == new IntPtr(-1))
        {
            Evidence.CreateWin32Error = LastError();
            request = IntPtr.Zero;
            throw new InvalidOperationException("power_request_create_failed");
        }
        Evidence.CreateWin32Error = 0;
        Evidence.Created = true;

        bool system = PowerSetRequest(request, RequestType.SystemRequired);
        Evidence.SetSystemWin32Error = system ? 0 : LastError();
        Evidence.SystemRequiredSet = system;
        if (!system) throw new InvalidOperationException("power_request_system_failed");

        bool display = PowerSetRequest(request, RequestType.DisplayRequired);
        Evidence.SetDisplayWin32Error = display ? 0 : LastError();
        Evidence.DisplayRequiredSet = display;
        if (!display) throw new InvalidOperationException("power_request_display_failed");
    }

    internal Observation Release()
    {
        if (released) return Evidence;
        released = true;
        Evidence.ReleaseAttempted = true;

        // Each cleanup is attempted independently. A failed Clear is retained
        // as failure even if closing the owned object subsequently succeeds.
        if (request != IntPtr.Zero)
        {
            if (Evidence.DisplayRequiredSet) Attempt(() =>
            {
                bool cleared = PowerClearRequest(request, RequestType.DisplayRequired);
                Evidence.ClearDisplayWin32Error = cleared ? 0 : LastError();
                Evidence.DisplayRequiredCleared = cleared;
            });
            if (Evidence.SystemRequiredSet) Attempt(() =>
            {
                bool cleared = PowerClearRequest(request, RequestType.SystemRequired);
                Evidence.ClearSystemWin32Error = cleared ? 0 : LastError();
                Evidence.SystemRequiredCleared = cleared;
            });
            Attempt(() =>
            {
                bool closed = CloseHandle(request);
                Evidence.CloseWin32Error = closed ? 0 : LastError();
                Evidence.HandleClosed = closed;
                if (closed) request = IntPtr.Zero;
            });
        }
        // Keep the input allocation alive on an unverified handle close; the
        // disposable process exit is the final boundary for that failed case.
        if (reason != IntPtr.Zero && request == IntPtr.Zero) Attempt(() =>
        {
            Marshal.FreeHGlobal(reason);
            reason = IntPtr.Zero;
            Evidence.ReasonBufferReleased = true;
        });
        return Evidence;
    }

    private void Attempt(Action action)
    {
        try { action(); }
        catch (Exception error) { Evidence.ReleaseExceptionHresult ??= unchecked((uint)error.HResult); }
    }

    private static uint LastError() => unchecked((uint)Marshal.GetLastWin32Error());
    public void Dispose() => Release();
}
