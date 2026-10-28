using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

namespace SessionContractExperiment;

// Observes the existing parent capture path. It never activates a window,
// switches desktops, changes DPI/display settings, or writes image data.
internal sealed class FrameProbe
{
    private const int MaximumDimension = 4096;
    private const int ColorCount = 8;
    private const int SampleStep = 4;
    private readonly Stopwatch clock = Stopwatch.StartNew();
    private FrameProbeSnapshot? last;
    private FrameCoverageObservation? lastCoverage;
    private long sequence;
    private long lastReportMilliseconds;
    private bool reported;
    private bool finalReported;

    internal FrameSamples? Capture(Control host, Control parent, Color[] palette, Action<string, object?> record)
    {
        if (palette.Length != ColorCount) throw new ArgumentException("Exactly eight challenge colors are required.", nameof(palette));
        Rectangle region = host.RectangleToScreen(host.ClientRectangle);
        ParentFrameGeometry geometry = ReadGeometry(host, parent, region);
        long currentSequence = ++sequence;
        long elapsed = clock.ElapsedMilliseconds;
        if (region.Width <= 0 || region.Height <= 0 || region.Width > MaximumDimension || region.Height > MaximumDimension)
        {
            Observe(new(currentSequence, elapsed, "region_rejected", geometry, null, 0, null), parent, record);
            return null;
        }

        Stopwatch capture = Stopwatch.StartNew();
        try
        {
            using Bitmap bitmap = new(region.Width, region.Height, PixelFormat.Format32bppArgb);
            using (Graphics graphics = Graphics.FromImage(bitmap))
                graphics.CopyFromScreen(region.Location, Point.Empty, region.Size, CopyPixelOperation.SourceCopy);
            FrameSamples samples = Analyze(bitmap, palette);
            Observe(new(currentSequence, elapsed, "captured", geometry, samples, capture.ElapsedMilliseconds, null), parent, record);
            return samples;
        }
        catch (Exception ex)
        {
            int code = ex is Win32Exception win32 ? win32.NativeErrorCode : ex.HResult;
            Observe(new(currentSequence, elapsed, "capture_failed", geometry, null, capture.ElapsedMilliseconds, code), parent, record);
            throw; // Preserve the existing failure behavior of CopyFromScreen.
        }
    }

    // The sample positions, tolerance, and required count are unchanged.
    // LockBits runs once; only sampled rows are copied, including negative stride.
    internal static FrameSamples Analyze(Bitmap bitmap, Color[] palette)
    {
        if (palette.Length != ColorCount) throw new ArgumentException("Exactly eight challenge colors are required.", nameof(palette));
        if (bitmap.Width <= 0 || bitmap.Height <= 0 || bitmap.Width > MaximumDimension || bitmap.Height > MaximumDimension)
            throw new ArgumentOutOfRangeException(nameof(bitmap));
        int rowBytes = checked(bitmap.Width * 4);
        byte[] row = ArrayPool<byte>.Shared.Rent(rowBytes);
        BitmapData? data = null;
        int[] counts = new int[ColorCount];
        int[] minimum = Enumerable.Repeat(255, ColorCount).ToArray();
        int[] red = palette.Select(color => (int)color.R).ToArray();
        int[] green = palette.Select(color => (int)color.G).ToArray();
        int[] blue = palette.Select(color => (int)color.B).ToArray();
        int total = 0, black = 0, white = 0;
        try
        {
            data = bitmap.LockBits(new Rectangle(0, 0, bitmap.Width, bitmap.Height), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            if (Math.Abs((long)data.Stride) < rowBytes) throw new InvalidOperationException("Invalid bitmap stride.");
            for (int y = 0; y < bitmap.Height; y += SampleStep)
            {
                Marshal.Copy(IntPtr.Add(data.Scan0, checked(y * data.Stride)), row, 0, rowBytes);
                for (int x = 0; x < bitmap.Width; x += SampleStep)
                {
                    int offset = x * 4;
                    int b = row[offset], g = row[offset + 1], r = row[offset + 2];
                    total++;
                    if ((r | g | b) == 0) black++;
                    if ((r & g & b) == 255) white++;
                    for (int i = 0; i < ColorCount; i++)
                    {
                        int distance = Math.Max(Math.Abs(r - red[i]), Math.Max(Math.Abs(g - green[i]), Math.Abs(b - blue[i])));
                        if (distance < minimum[i]) minimum[i] = distance;
                        if (distance <= 3) counts[i]++;
                    }
                }
            }
            return new(total, black, white, counts, minimum);
        }
        finally
        {
            try { if (data is not null) bitmap.UnlockBits(data); }
            finally { ArrayPool<byte>.Shared.Return(row, clearArray: true); }
        }
    }

    private void Observe(FrameProbeSnapshot snapshot, Control parent, Action<string, object?> record)
    {
        last = snapshot;
        long now = clock.ElapsedMilliseconds;
        if (reported && now - lastReportMilliseconds < 10_000) return;
        string phase = reported ? "periodic" : "first";
        reported = true;
        lastReportMilliseconds = now;
        record("parent_frame_probe", new { phase, snapshot });
        // Resolve image/class categories only on bounded diagnostic reports,
        // not on every 500ms frame capture. These queries never affect a match.
        try
        {
            OwnWindowCoverage coverage = OwnWindowPresentation.Observe((Form)parent);
            lastCoverage = new(snapshot.Sequence, snapshot.ElapsedMilliseconds, coverage, null);
        }
        catch (Exception exception)
        {
            lastCoverage = new(snapshot.Sequence, snapshot.ElapsedMilliseconds, null, exception.HResult);
        }
        record("parent_window_coverage", new { phase, snapshot = lastCoverage });
    }

    // Re-emits the most recent sampled pass, before cleanup changes visibility.
    // This does not take another screenshot or turn a diagnostic into a pass.
    internal void RecordFinal(Action<string, object?> record)
    {
        if (last is null || finalReported) return;
        finalReported = true;
        record("parent_frame_probe", new { phase = "final", snapshot = last });
        if (lastCoverage is not null)
            record("parent_window_coverage", new { phase = "final", snapshot = lastCoverage });
    }

    private static ParentFrameGeometry ReadGeometry(Control host, Control parent, Rectangle region)
    {
        IntPtr hostWindow = host.Handle, parentWindow = parent.Handle;
        Rectangle screen = SystemInformation.VirtualScreen;
        Rectangle overlap = Rectangle.Intersect(region, screen);
        IntPtr root = GetAncestor(parentWindow, 2 /* GA_ROOT */);
        int? rootError = root == IntPtr.Zero ? Marshal.GetLastWin32Error() : null;
        IntPtr foreground = GetForegroundWindow();
        IntPtr foregroundRoot = foreground == IntPtr.Zero ? IntPtr.Zero : GetAncestor(foreground, 2);
        bool? foregroundIsOwn = root == IntPtr.Zero || foregroundRoot == IntPtr.Zero ? null : root == foregroundRoot;

        int ownMask = 0, noWindowMask = 0, unresolvedRootMask = 0;
        int points = 0;
        if (region.Width > 0 && region.Height > 0 && region.Width <= MaximumDimension && region.Height <= MaximumDimension)
        {
            // A fixed 3x3 grid, row-major, at 1/6, 3/6, and 5/6 of the host.
            // Report only ownership bits, never handles, titles, or class names.
            for (int y = 0; y < 3; y++)
            for (int x = 0; x < 3; x++)
            {
                NativePoint point = new(region.Left + (int)((long)(2 * x + 1) * region.Width / 6),
                    region.Top + (int)((long)(2 * y + 1) * region.Height / 6));
                int bit = 1 << points++;
                IntPtr hit = WindowFromPoint(point);
                if (hit == IntPtr.Zero) { noWindowMask |= bit; continue; }
                IntPtr hitRoot = GetAncestor(hit, 2);
                if (hitRoot == IntPtr.Zero) { unresolvedRootMask |= bit; continue; }
                if (root != IntPtr.Zero && root == hitRoot) ownMask |= bit;
            }
        }

        bool? inputDesktop = null;
        int? desktopError = null;
        bool desktopQuerySucceeded = false;
        uint? desktopResultBytes = null;
        IntPtr desktop = GetThreadDesktop(GetCurrentThreadId()); // Borrowed; do not close.
        if (desktop == IntPtr.Zero) desktopError = Marshal.GetLastWin32Error();
        else if (GetUserObjectInformationBoolean(desktop, 6 /* UOI_IO */, out int input, sizeof(int), out uint needed))
        {
            desktopQuerySucceeded = true;
            desktopResultBytes = needed;
            if (needed == sizeof(int)) inputDesktop = input != 0;
        }
        else { desktopError = Marshal.GetLastWin32Error(); desktopResultBytes = needed; }

        NativePoint topLeft = new(region.Left, region.Top), bottomRight = new(region.Right, region.Bottom);
        bool converted = LogicalToPhysicalPointForPerMonitorDPI(hostWindow, ref topLeft) &&
            LogicalToPhysicalPointForPerMonitorDPI(hostWindow, ref bottomRight);
        FrameRectangle? physical = converted ? new(topLeft.X, topLeft.Y, bottomRight.X - topLeft.X, bottomRight.Y - topLeft.Y) : null;
        uint cloaked = 0;
        int cloakResult = DwmGetWindowAttribute(parentWindow, 14 /* DWMWA_CLOAKED */, out cloaked, sizeof(uint));

        return new(FrameRectangle.From(region), FrameRectangle.From(host.ClientRectangle), FrameRectangle.From(screen),
            FrameRectangle.From(overlap), region.Width > 0 && region.Height > 0 && screen.Contains(region), physical,
            GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()), GetDpiForWindow(hostWindow),
            IsWindowVisible(parentWindow), IsWindowVisible(hostWindow), IsIconic(parentWindow), foregroundIsOwn,
            inputDesktop, desktopQuerySucceeded, desktopResultBytes, desktopError,
            points, root != IntPtr.Zero ? ownMask : null, noWindowMask, unresolvedRootMask, rootError,
            cloakResult >= 0 ? cloaked : null, cloakResult);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        internal int X, Y;
        internal NativePoint(int x, int y) { X = x; Y = y; }
    }
    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetThreadDesktop(uint threadId);
    [DllImport("user32.dll", EntryPoint = "GetUserObjectInformationW", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformationBoolean(IntPtr handle, int index, out int value, uint length, out uint needed);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetAncestor(IntPtr window, uint flags);
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr WindowFromPoint(NativePoint point);
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetThreadDpiAwarenessContext();
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern int GetAwarenessFromDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern uint GetDpiForWindow(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogicalToPhysicalPointForPerMonitorDPI(IntPtr window, ref NativePoint point);
    [DllImport("dwmapi.dll", ExactSpelling = true)]
    private static extern int DwmGetWindowAttribute(IntPtr window, uint attribute, out uint value, uint size);
}

internal readonly record struct FrameRectangle(int X, int Y, int Width, int Height)
{
    internal static FrameRectangle From(Rectangle value) => new(value.X, value.Y, value.Width, value.Height);
}

internal sealed record FrameSamples(int SampleCount, int BlackSamples, int WhiteSamples,
    int[] CountsWithin3, int[] MinChebyshevDistance)
{
    public bool MatchesChallenge => CountsWithin3.Length == 8 && CountsWithin3.All(count => count >= 80);
}

internal sealed record FrameProbeSnapshot(long Sequence, long ElapsedMilliseconds, string CaptureStatus,
    ParentFrameGeometry Geometry, FrameSamples? Pixels, long CaptureMilliseconds, int? CaptureError);

internal sealed record FrameCoverageObservation(long FrameSequence, long FrameElapsedMilliseconds,
    OwnWindowCoverage? Coverage, int? DiagnosticHresult);

internal sealed record ParentFrameGeometry(FrameRectangle ClientRegion, FrameRectangle HostClientRectangle,
    FrameRectangle VirtualScreen, FrameRectangle VirtualScreenIntersection, bool EntireRegionInsideVirtualScreen,
    FrameRectangle? PhysicalClientRegion, int ThreadDpiAwareness, uint HostDpi,
    bool ParentWindowVisible, bool HostWindowVisible, bool ParentWindowIconic, bool? ForegroundRootIsParent,
    bool? CurrentDesktopReceivesInput, bool InputDesktopQuerySucceeded, uint? InputDesktopResultBytes,
    int? InputDesktopQueryError, int HitTestPointCount, int? OwnRootHitMask,
    int NoWindowHitMask, int UnresolvedRootHitMask, int? ParentRootQueryError, uint? ParentCloakedFlags, int ParentCloakHresult);
