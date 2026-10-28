using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SessionContractExperiment;

// Read-only diagnostics for this witness's own UI. These observations are never
// substitutes for the parent's existing RDP frame acceptance check.
internal sealed class WitnessRenderEvidence
{
    private const int RegularSnapshotLimit = 14;
    private const int TotalSnapshotLimit = 16;
    private readonly string output;
    private readonly Color[] palette;
    private readonly Snapshot state;
    private readonly object gate = new();
    private bool ownsOutput;
    private int attempts;
    private static readonly JsonSerializerOptions JsonOptions = new()
    { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    private sealed class Snapshot
    {
        public string Schema { get; } = "witness-render/v1";
        public long Sequence { get; set; }
        public required string Nonce { get; init; }
        public uint SessionId { get; init; }
        public required string IdentityDigest { get; init; }
        public int ProcessId { get; init; } = Environment.ProcessId;
        public string Stage { get; set; } = "identity_written";
        public string? ObservedUtc { get; set; }
        public bool FinalSnapshot { get; set; }
        public string? FirstShownUtc { get; set; }
        public int PaintCount { get; set; }
        public string? LastPaintUtc { get; set; }
        public bool HandleCreated { get; set; }
        public bool? IsWindowVisible { get; set; }
        public bool? IsMinimized { get; set; }
        public int? DeviceDpi { get; set; }
        public Rect? FormBounds { get; set; }
        public Rect? ClientBounds { get; set; }
        public Rect? ClientScreenBounds { get; set; }
        public string CurrentWindowStationCategory { get; set; } = "unavailable";
        public int WindowStationQueryWin32Error { get; set; }
        public int WindowStationQueryHresult { get; set; }
        public string CurrentDesktopCategory { get; set; } = "unavailable";
        public int DesktopQueryWin32Error { get; set; }
        public int DesktopQueryHresult { get; set; }
        public bool DesktopInputQuerySucceeded { get; set; }
        public bool? DesktopReceivesInput { get; set; }
        public int DesktopInputQueryWin32Error { get; set; }
        public int DesktopInputQueryHresult { get; set; }
        public string FrameProbeStatus { get; set; } = "not_attempted";
        public string? FrameProbeUtc { get; set; }
        public int FrameProbeCount { get; set; }
        public Rect? FrameProbeRegion { get; set; }
        public int FrameSampleStride { get; } = 4;
        public int FrameColorTolerance { get; } = 3;
        public int[]? FramePaletteCounts { get; set; }
        public int[]? FrameClosestColorDistances { get; set; }
        public int FrameSampleCount { get; set; }
        public int FrameNonblackSamples { get; set; }
        public int FrameProbeWin32Error { get; set; }
        public int FrameProbeHresult { get; set; }
        public int DiagnosticHresult { get; set; }
        public string? FirstExceptionStage { get; set; }
        public string? FirstExceptionCategory { get; set; }
        public int? FirstExceptionHresult { get; set; }
        public int? FirstExceptionWin32Error { get; set; }
        public int ExceptionCount { get; set; }
        public int ReportWriteFailureCount { get; set; }
        public int LastReportWriteHresult { get; set; }
        public int? CloseReason { get; set; }
        public int? WitnessExitCode { get; set; }
    }

    private readonly record struct Rect(int X, int Y, int Width, int Height)
    { internal static Rect From(Rectangle value) => new(value.X, value.Y, value.Width, value.Height); }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetProcessWindowStation();
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetThreadDesktop(uint threadId);
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UserObjectInformation(IntPtr handle, int index, IntPtr information, uint length, out uint needed);
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UserObjectBoolean(IntPtr handle, int index, out int value, uint length, out uint needed);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr window);

    internal WitnessRenderEvidence(string identityOutput, string nonce, uint session, string identityDigest)
    {
        output = Path.Combine(Path.GetDirectoryName(identityOutput) ?? throw new ExperimentFailure("witness_report_directory_missing"), "witness-render.json");
        if (File.Exists(output)) throw new ExperimentFailure("witness_render_report_already_exists");
        palette = Program.ChallengeColors(nonce);
        state = new Snapshot { Nonce = nonce, SessionId = session, IdentityDigest = identityDigest };
    }

    internal void IdentityWritten()
    {
        lock (gate)
        {
            state.Stage = "identity_written";
            try { InspectUserObjects(); } catch (Exception ex) { state.DiagnosticHresult = ex.HResult; }
            Publish(false);
        }
    }

    internal void Shown(Form form)
    {
        lock (gate) { state.FirstShownUtc ??= DateTimeOffset.UtcNow.ToString("O"); }
        Capture(form, "shown", captureFrame: false);
    }

    internal void PaintCompleted()
    {
        lock (gate)
        {
            if (state.PaintCount < int.MaxValue) state.PaintCount++;
            state.LastPaintUtc = DateTimeOffset.UtcNow.ToString("O");
        }
    }

    internal bool UiFailed { get { lock (gate) return state.ExceptionCount != 0; } }

    // Called only on the witness's own UI thread, after a paint has returned.
    internal void Capture(Form form, string stage, bool captureFrame, bool final = false, int? closeReason = null)
    {
        lock (gate)
        {
            if (attempts >= (final ? TotalSnapshotLimit : RegularSnapshotLimit)) return;
            state.Stage = stage;
            state.CloseReason = closeReason ?? state.CloseReason;
            try
            {
                state.HandleCreated = form.IsHandleCreated && !form.IsDisposed;
                state.FormBounds = Rect.From(form.Bounds);
                state.ClientBounds = Rect.From(form.ClientRectangle);
                state.DeviceDpi = form.DeviceDpi;
                if (state.HandleCreated)
                {
                    state.IsWindowVisible = IsWindowVisible(form.Handle);
                    state.IsMinimized = IsIconic(form.Handle);
                    state.ClientScreenBounds = Rect.From(form.RectangleToScreen(form.ClientRectangle));
                }
                InspectUserObjects();
                if (captureFrame) CaptureOwnFrame(form);
            }
            catch (Exception ex) { state.DiagnosticHresult = ex.HResult; }
            Publish(final);
        }
    }

    internal void RecordException(string stage, Exception exception)
    {
        lock (gate)
        {
            state.ExceptionCount++;
            if (state.FirstExceptionHresult is null)
            {
                state.FirstExceptionStage = stage;
                state.FirstExceptionCategory = exception is Win32Exception ? "win32" : "managed";
                state.FirstExceptionHresult = exception.HResult;
                state.FirstExceptionWin32Error = exception is Win32Exception win32 ? win32.NativeErrorCode : null;
            }
            state.Stage = "exception";
            state.WitnessExitCode = 2;
            Publish(true);
        }
    }

    internal void Returning(int exitCode)
    {
        lock (gate) { state.Stage = "witness_returning"; state.WitnessExitCode = exitCode; Publish(true); }
    }

    private void InspectUserObjects()
    {
        // Both handles are borrowed. Never close them, switch desktop, or edit a DACL.
        IntPtr station = GetProcessWindowStation();
        int stationError = station == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        state.CurrentWindowStationCategory = station == IntPtr.Zero ? "unavailable" : Category(station, true, out stationError);
        state.WindowStationQueryWin32Error = stationError;
        state.WindowStationQueryHresult = FromWin32(stationError);
        IntPtr desktop = GetThreadDesktop(GetCurrentThreadId());
        int desktopError = desktop == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
        state.CurrentDesktopCategory = desktop == IntPtr.Zero ? "unavailable" : Category(desktop, false, out desktopError);
        state.DesktopQueryWin32Error = desktopError;
        state.DesktopQueryHresult = FromWin32(desktopError);
        bool succeeded = false;
        int input = 0, inputError = desktopError;
        if (desktop != IntPtr.Zero)
        {
            succeeded = UserObjectBoolean(desktop, 6 /* UOI_IO */, out input, sizeof(int), out _);
            inputError = succeeded ? 0 : Marshal.GetLastWin32Error();
        }
        state.DesktopInputQuerySucceeded = succeeded;
        state.DesktopReceivesInput = succeeded ? input != 0 : null;
        state.DesktopInputQueryWin32Error = inputError;
        state.DesktopInputQueryHresult = FromWin32(inputError);
    }

    private static string Category(IntPtr handle, bool station, out int error)
    {
        bool initial = UserObjectInformation(handle, 2 /* UOI_NAME */, IntPtr.Zero, 0, out uint bytes);
        error = initial ? 0 : Marshal.GetLastWin32Error();
        if ((!initial && error != 122 /* ERROR_INSUFFICIENT_BUFFER */) || bytes < 2 || bytes > 32768 || bytes % 2 != 0)
        { if (error == 0) error = 13 /* ERROR_INVALID_DATA */; return "unavailable"; }
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)bytes));
        try
        {
            if (!UserObjectInformation(handle, 2, buffer, bytes, out uint needed))
            { error = Marshal.GetLastWin32Error(); return "unavailable"; }
            if (needed < 2 || needed > bytes || needed % 2 != 0) { error = 13; return "unavailable"; }
            string name = Marshal.PtrToStringUni(buffer, checked((int)needed / 2))?.TrimEnd('\0') ?? "";
            error = 0;
            if (station) return string.Equals(name, "WinSta0", StringComparison.OrdinalIgnoreCase) ? "interactive" : "other";
            if (string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase)) return "default";
            if (string.Equals(name, "Winlogon", StringComparison.OrdinalIgnoreCase)) return "winlogon";
            if (string.Equals(name, "Disconnect", StringComparison.OrdinalIgnoreCase)) return "disconnect";
            return "other"; // Never publish an arbitrary window-station or desktop name.
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private void CaptureOwnFrame(Form form)
    {
        state.FrameProbeCount++;
        state.FrameProbeUtc = DateTimeOffset.UtcNow.ToString("O");
        state.FramePaletteCounts = null;
        state.FrameClosestColorDistances = null;
        state.FrameProbeRegion = null;
        state.FrameSampleCount = 0;
        state.FrameNonblackSamples = 0;
        state.FrameProbeWin32Error = 0;
        state.FrameProbeHresult = 0;
        if (!state.HandleCreated || state.PaintCount == 0 || state.IsWindowVisible != true || state.IsMinimized == true)
        { state.FrameProbeStatus = "ui_not_ready"; return; }
        Rectangle region = form.RectangleToScreen(form.ClientRectangle);
        state.FrameProbeRegion = Rect.From(region);
        if (region.Width <= 0 || region.Height <= 0 || region.Width > 4096 || region.Height > 4096 ||
            (long)region.Width * region.Height > 4 * 1024 * 1024)
        { state.FrameProbeStatus = "region_out_of_bounds"; return; }
        try
        {
            using Bitmap bitmap = new(region.Width, region.Height);
            using (Graphics graphics = Graphics.FromImage(bitmap))
                graphics.CopyFromScreen(region.Location, Point.Empty, region.Size, CopyPixelOperation.SourceCopy);
            int[] counts = new int[palette.Length];
            int[] closest = Enumerable.Repeat(255, palette.Length).ToArray();
            for (int y = 0; y < bitmap.Height; y += 4)
            for (int x = 0; x < bitmap.Width; x += 4)
            {
                Color pixel = bitmap.GetPixel(x, y);
                state.FrameSampleCount++;
                if (pixel.R != 0 || pixel.G != 0 || pixel.B != 0) state.FrameNonblackSamples++;
                for (int index = 0; index < palette.Length; index++)
                {
                    int distance = Math.Max(Math.Abs(pixel.R - palette[index].R),
                        Math.Max(Math.Abs(pixel.G - palette[index].G), Math.Abs(pixel.B - palette[index].B)));
                    closest[index] = Math.Min(closest[index], distance);
                    if (distance <= 3) counts[index]++;
                }
            }
            state.FramePaletteCounts = counts;
            state.FrameClosestColorDistances = closest;
            state.FrameProbeStatus = "sampled";
            // The bitmap is disposed here. Only counters/distances are emitted;
            // no image, pixel array, desktop text, or screenshot is serialized.
        }
        catch (Exception ex)
        {
            state.FrameProbeStatus = "capture_failed";
            state.FrameProbeHresult = ex.HResult;
            state.FrameProbeWin32Error = ex is Win32Exception win32 ? win32.NativeErrorCode : 0;
        }
    }

    private void Publish(bool final)
    {
        if (attempts >= (final ? TotalSnapshotLimit : RegularSnapshotLimit)) return;
        attempts++;
        state.Sequence = attempts;
        state.ObservedUtc = DateTimeOffset.UtcNow.ToString("O");
        state.FinalSnapshot = final;
        string temporary = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        bool ownTemporary = false;
        try
        {
            using (FileStream stream = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                ownTemporary = true;
                JsonSerializer.Serialize(stream, state, JsonOptions);
                if (stream.Length > 64 * 1024) throw new ExperimentFailure("witness_render_report_exceeds_bound");
            }
            // A same-directory rename publishes only a complete JSON snapshot.
            // The first write must create a new path. Subsequent writes replace
            // only the report created by this recorder in the owned test folder.
            File.Move(temporary, output, ownsOutput);
            ownsOutput = true;
        }
        catch (Exception ex)
        {
            state.ReportWriteFailureCount++;
            state.LastReportWriteHresult = ex.HResult;
            Console.Error.WriteLine("witness_render_write_failed;hresult=" + ex.HResult.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        finally
        {
            if (ownTemporary && File.Exists(temporary))
                try { File.Delete(temporary); } catch { /* Own temporary only; no claim of cleanup. */ }
        }
    }

    private static int FromWin32(int error) => error <= 0 ? error : unchecked((int)(0x80070000u | ((uint)error & 0xffff)));
}
