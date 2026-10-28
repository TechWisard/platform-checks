using System.Runtime.InteropServices;

namespace SessionContractExperiment;

// Changes only the two forms owned by this experiment. Call Present once per
// form, never from a timer or frame retry. Observation does not change focus.
internal static class OwnWindowPresentation
{
    private const int PreferredWidth = 1024;
    private const int PreferredHeight = 768;

    internal static void Configure(Form form)
    {
        form.StartPosition = FormStartPosition.Manual;
        form.FormBorderStyle = FormBorderStyle.None;
        form.WindowState = FormWindowState.Normal;
        form.TopMost = true;
        form.Bounds = BoundedPrimaryRectangle();
    }

    internal static void Present(Form form)
    {
        if (!form.IsHandleCreated || form.IsDisposed || !form.TopLevel)
            throw new ExperimentFailure("own_window_presentation_not_ready");
        // Re-evaluate after Show/Load, when the session display is established.
        // Borderless bounds keep the client area inside this monitor; neither
        // the display mode nor the process/thread DPI awareness is changed.
        form.WindowState = FormWindowState.Normal;
        form.Bounds = BoundedPrimaryRectangle();
        form.TopMost = true;
        form.BringToFront();
        form.Activate(); // A request, not proof: foreground policy can deny it.
        form.Invalidate(invalidateChildren: true);
        form.Update();
    }

    private static Rectangle BoundedPrimaryRectangle()
    {
        Rectangle monitor = (Screen.PrimaryScreen ??
            throw new ExperimentFailure("presentation_primary_monitor_unavailable")).Bounds;
        if (monitor.Width <= 0 || monitor.Height <= 0)
            throw new ExperimentFailure("presentation_monitor_bounds_invalid");
        return new Rectangle(monitor.Location, new Size(
            Math.Min(PreferredWidth, monitor.Width), Math.Min(PreferredHeight, monitor.Height)));
    }

    internal static OwnWindowCoverage Observe(Form form)
    {
        if (!form.IsHandleCreated || form.IsDisposed)
            throw new ExperimentFailure("own_window_observation_not_ready");
        IntPtr window = form.Handle;
        Rectangle region = form.RectangleToScreen(form.ClientRectangle);
        Rectangle screen = SystemInformation.VirtualScreen;
        IntPtr root = GetAncestor(window, 2 /* GA_ROOT */);
        IntPtr foreground = GetForegroundWindow();
        IntPtr foregroundRoot = foreground == IntPtr.Zero ? IntPtr.Zero : GetAncestor(foreground, 2);
        bool? foregroundIsOwn = root == IntPtr.Zero || foregroundRoot == IntPtr.Zero ? null : root == foregroundRoot;

        int points = 0, ownMask = 0, noWindowMask = 0, unresolvedMask = 0;
        IntPtr[] hitRoots = new IntPtr[9];
        if (region.Width is > 0 and <= 4096 && region.Height is > 0 and <= 4096)
        {
            // Same row-major 3x3 grid used by the independent parent probe.
            // No handles, titles, class names, or foreign identities are emitted.
            for (int y = 0; y < 3; y++)
            for (int x = 0; x < 3; x++)
            {
                NativePoint point = new(region.Left + (int)((long)(2 * x + 1) * region.Width / 6),
                    region.Top + (int)((long)(2 * y + 1) * region.Height / 6));
                int bit = 1 << points++;
                IntPtr hit = WindowFromPoint(point);
                if (hit == IntPtr.Zero) { noWindowMask |= bit; continue; }
                IntPtr hitRoot = GetAncestor(hit, 2);
                hitRoots[points - 1] = hitRoot;
                if (hitRoot == IntPtr.Zero) { unresolvedMask |= bit; continue; }
                if (root != IntPtr.Zero && hitRoot == root) ownMask |= bit;
            }
        }

        NativePoint topLeft = new(region.Left, region.Top), bottomRight = new(region.Right, region.Bottom);
        bool converted = LogicalToPhysicalPointForPerMonitorDPI(window, ref topLeft) &&
            LogicalToPhysicalPointForPerMonitorDPI(window, ref bottomRight);
        FrameRectangle? physical = converted ?
            new(topLeft.X, topLeft.Y, bottomRight.X - topLeft.X, bottomRight.Y - topLeft.Y) : null;
        int cloakHresult = DwmGetWindowAttribute(window, 14 /* DWMWA_CLOAKED */, out uint cloaked, sizeof(uint));
        return new(FrameRectangle.From(region), FrameRectangle.From(screen),
            region.Width > 0 && region.Height > 0 && screen.Contains(region), physical,
            form.TopMost, IsWindowVisible(window), IsWindowEnabled(window), IsIconic(window),
            root != IntPtr.Zero, foregroundRoot != IntPtr.Zero, foregroundIsOwn,
            points, root != IntPtr.Zero ? ownMask : null, noWindowMask, unresolvedMask,
            cloakHresult >= 0 ? cloaked : null, cloakHresult,
            WindowCoverageDiagnostics.Capture(form, root, foregroundRoot, hitRoots));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        internal int X, Y;
        internal NativePoint(int x, int y) { X = x; Y = y; }
    }

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetAncestor(IntPtr window, uint flags);
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr WindowFromPoint(NativePoint point);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogicalToPhysicalPointForPerMonitorDPI(IntPtr window, ref NativePoint point);
    [DllImport("dwmapi.dll", ExactSpelling = true)]
    private static extern int DwmGetWindowAttribute(IntPtr window, uint attribute, out uint value, uint size);
}

internal sealed record OwnWindowCoverage(FrameRectangle ClientScreenBounds, FrameRectangle VirtualScreen,
    bool EntireRegionInsideVirtualScreen, FrameRectangle? PhysicalClientScreenBounds,
    bool TopMostRequested, bool WindowVisible, bool WindowEnabled, bool WindowIconic,
    bool OwnRootResolved, bool ForegroundRootResolved, bool? ForegroundRootIsOwn,
    int HitTestPointCount, int? OwnRootHitMask, int NoWindowHitMask, int UnresolvedRootHitMask,
    uint? CloakedFlags, int CloakHresult, WindowCoverageDiagnosticSnapshot Diagnostics);
