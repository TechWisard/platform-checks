using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SessionContractExperiment;

// An optional, bounded standard-window input test. This deliberately uses the
// parent's ordinary input queue. Its result is separate from direct-channel and
// physical-device isolation evidence.
internal static class WindowInputExperiment
{
    internal static async Task Run(Form parent, RdpHost host, object control, Evidence evidence,
        string witnessIdentityFile, string bindingNonce, uint childSession, string identityDigest,
        Action requireOwnership, TimeSpan remaining)
    {
        if (!evidence.WindowInputRequested || evidence.DirectInputRequested ||
            !evidence.FrameChallengeVerified || !evidence.DifferentAccountVerified ||
            evidence.ChildMatchesCreatedAccountSid != true || !evidence.WitnessInExpectedSession ||
            !evidence.WitnessIdentityMatches)
            throw new ExperimentFailure("window_input_frame_and_account_gate_not_met");
        if (remaining < TimeSpan.FromSeconds(12))
            throw new ExperimentFailure("window_input_budget_unavailable");

        TimeSpan budget = remaining < TimeSpan.FromSeconds(25) ? remaining : TimeSpan.FromSeconds(25);
        Stopwatch elapsed = Stopwatch.StartNew();
        string path = Path.Combine(Path.GetDirectoryName(witnessIdentityFile)!, "witness-input.json");
        long lastSequence = 0;
        InputObservation? latest = null;
        WindowInputTarget? target = null;
        WindowInputEmitter? emitter = null;
        WindowMessageObservation? messages = null;
        InputPoint? cursorBefore = null;
        InputPoint? cursorAfter = null;
        bool complete = false;

        try
        {
            requireOwnership();
            target = new WindowInputTarget(parent, host, control, evidence.Event);
            // This is a single request to the actual COM object's own window,
            // after verifying our Form already owns the foreground. No other
            // thread's queue or foreign window is attached or activated.
            target.SelectOwnFocusOnce();
            messages = new WindowMessageObservation(parent.Handle, target.Window);
            cursorBefore = WindowInputNative.Cursor();

            void RequireTarget()
            {
                requireOwnership();
                target.Require();
                if (messages.Overflow || messages.OutsideTargetInput != 0)
                    throw new ExperimentFailure("window_input_left_own_control");
            }

            void Check()
            {
                if (elapsed.Elapsed >= budget)
                    throw new ExperimentFailure("window_input_timeout");
                RequireTarget();
            }

            InputObservation Read()
            {
                Check();
                InputObservation report = InputReport.Read(path, bindingNonce, childSession, identityDigest);
                if (report.Sequence < lastSequence)
                    throw new ExperimentFailure("window_input_report_sequence_regressed");
                lastSequence = report.Sequence;
                latest = report;
                RequireHealthy(report);
                return report;
            }

            async Task<InputObservation> Wait(Func<InputObservation, bool> predicate)
            {
                while (true)
                {
                    Check();
                    if (File.Exists(path))
                    {
                        InputObservation report = Read();
                        if (predicate(report)) return report;
                    }
                    await Task.Delay(60);
                }
            }

            InputObservation baseline = await Wait(r => r.Shown);
            long baselineSequence = baseline.Sequence;
            baseline = await Wait(r => r.Sequence > baselineSequence);
            if (baseline.CharacterCount != 0 || baseline.ReceivedHex.Length != 0 ||
                baseline.LeftDownCount != 0 || baseline.LeftUpCount != 0 ||
                baseline.KeyDownCount != 0 || baseline.KeyUpCount != 0)
                throw new ExperimentFailure("window_input_witness_baseline_not_empty");

            InputRectangle desktop = baseline.VirtualScreen;
            if (baseline.MonitorCount != 1 || desktop.X != 0 || desktop.Y != 0 ||
                desktop.Width is <= 0 or > 4096 || desktop.Height is <= 0 or > 4096 ||
                !baseline.PhysicalEqualsLogical ||
                !desktop.Rectangle.Contains(baseline.PhysicalClientScreen.Rectangle) ||
                target.ClientRectangle.Width != desktop.Width || target.ClientRectangle.Height != desktop.Height)
                throw new ExperimentFailure("window_input_geometry_not_one_to_one");
            if (!baseline.CursorQuerySucceeded)
                throw new ExperimentFailure("window_input_child_cursor_unavailable", baseline.CursorError);

            Rectangle safe = baseline.PhysicalClientScreen.Rectangle;
            safe.Inflate(-48, -48);
            if (safe.Width < 64 || safe.Height < 64)
                throw new ExperimentFailure("window_input_safe_region_too_small");
            InputPoint childPoint;
            InputPoint parentPoint;
            do
            {
                childPoint = new(RandomNumberGenerator.GetInt32(safe.Left, safe.Right),
                    RandomNumberGenerator.GetInt32(safe.Top, safe.Bottom));
                parentPoint = new(target.ClientRectangle.X + childPoint.X, target.ClientRectangle.Y + childPoint.Y);
            }
            while (childPoint == baseline.Cursor || parentPoint == cursorBefore);

            // Decimal digits are valid hexadecimal characters for the existing
            // witness. They avoid Caps Lock and Shift. The expected sequence is
            // generated here and never sent through a file, argument or digest.
            string expectedText = string.Create(8, 0, (text, _) =>
            {
                for (int i = 0; i < text.Length; i++)
                    text[i] = (char)('0' + RandomNumberGenerator.GetInt32(10));
            });
            emitter = new WindowInputEmitter(target, RequireTarget);
            ushort[] scans = expectedText.Select(target.DigitScanCode).ToArray();
            evidence.Event("window_input_ready", new
            {
                geometry = "one_parent_client_pixel_per_child_desktop_pixel",
                parent_client = target.ClientRectangle,
                child_desktop = desktop,
                target_window_from_com = true,
                focus_inside_own_control = true,
                keyboard_mode = "layout_checked_digit_scancodes",
                global_input_queue = true,
                physical_device_isolation = false
            });

            Check();
            emitter.Move(parentPoint);
            InputObservation moved = await Wait(r => r.MoveSequence > baseline.MoveSequence && r.Sequence > baseline.Sequence);
            RequireGeometry(moved, baseline);
            if (moved.MovePoint != childPoint || !moved.MoveHitOwnRoot ||
                moved.CharacterCount != 0 || moved.LeftDownCount != 0 || moved.LeftUpCount != 0 ||
                moved.KeyDownCount != 0 || moved.KeyUpCount != 0 || WindowInputNative.Cursor() != parentPoint)
                throw new ExperimentFailure("window_input_move_coordinate_or_baseline_mismatch");
            evidence.Event("window_input_move_observed", new { child = childPoint, parent = parentPoint });

            Check();
            emitter.LeftClick(parentPoint);
            InputObservation clicked = await Wait(r => r.LeftDownCount == 1 && r.LeftUpCount == 1);
            RequireGeometry(clicked, baseline);
            if (clicked.LeftDownPoint != childPoint || clicked.LeftUpPoint != childPoint ||
                clicked.LeftDownSequence <= moved.MoveSequence || clicked.LeftUpSequence <= clicked.LeftDownSequence ||
                clicked.CharacterCount != 0 || clicked.KeyDownCount != 0 || clicked.KeyUpCount != 0)
                throw new ExperimentFailure("window_input_button_sequence_or_point_mismatch");
            evidence.WindowChildReceivedExpectedButtonSequence = true;
            evidence.Event("window_input_click_observed");

            for (int i = 0; i < expectedText.Length; i++)
            {
                Check();
                emitter.KeyPair(scans[i], expectedText[i], parentPoint);
                int expectedCount = i + 1;
                InputObservation partial = await Wait(r => r.CharacterCount >= expectedCount &&
                    r.KeyDownCount >= expectedCount && r.KeyUpCount >= expectedCount);
                RequireGeometry(partial, baseline);
                if (partial.CharacterCount != expectedCount || partial.KeyDownCount != expectedCount ||
                    partial.KeyUpCount != expectedCount || partial.ReceivedHex != expectedText[..expectedCount] ||
                    partial.LeftDownCount != 1 || partial.LeftUpCount != 1)
                    throw new ExperimentFailure("window_input_text_or_key_sequence_mismatch");
            }

            void RequireFinal(InputObservation report)
            {
                RequireGeometry(report, baseline);
                if (report.CharacterCount != 8 || report.KeyDownCount != 8 || report.KeyUpCount != 8 ||
                    report.ReceivedHex != expectedText || report.LeftDownCount != 1 || report.LeftUpCount != 1 ||
                    report.LeftDownPoint != childPoint || report.LeftUpPoint != childPoint)
                    throw new ExperimentFailure("window_input_changed_during_quiet_interval");
            }

            Stopwatch quiet = Stopwatch.StartNew();
            InputObservation final = Read();
            while (quiet.Elapsed < TimeSpan.FromSeconds(1))
            {
                RequireFinal(final);
                await Task.Delay(60);
                final = Read();
            }
            long quietEndSequence = final.Sequence;
            final = await Wait(r => { RequireFinal(r); return r.Sequence > quietEndSequence; });
            RequireFinal(final);
            Check();
            emitter.RequireReleased();
            if (messages.KeyDown != 8 || messages.KeyUp != 8 || messages.LeftDown != 1 || messages.LeftUp != 1 ||
                messages.SystemKeys != 0 || messages.OtherButtons != 0)
                throw new ExperimentFailure("window_input_parent_message_sequence_mismatch");
            evidence.WindowChildReceivedExpectedText = true;
            complete = true;
        }
        finally
        {
            // At most one own keyboard release and one own button release. A
            // changed target makes cleanup unverified; it does not authorize an
            // event aimed at a foreign foreground window or cursor location.
            evidence.WindowInputCleanupVerified = emitter is null || await emitter.ReleasePending(evidence.Event);
            if (emitter is not null)
            {
                evidence.Event("window_input_submission", new
                {
                    calls = emitter.Calls,
                    requested = emitter.Requested,
                    inserted = emitter.Inserted,
                    cleanup_calls = emitter.CleanupCalls,
                    cleanup_inserted = emitter.CleanupInserted,
                    cleanup_observations = emitter.CleanupObservations,
                    pending_key = emitter.KeyPending,
                    pending_button = emitter.ButtonPending,
                    submission_unknown = emitter.SubmissionUnknown,
                    cleanup_verified = evidence.WindowInputCleanupVerified
                });
            }
            if (InputNative.GetCursorPos(out InputNative.Point cursor)) cursorAfter = cursor.Value;
            if (messages is not null)
            {
                evidence.Event("window_input_parent_observation", new
                {
                    messages.KeyDown, messages.KeyUp, messages.Characters,
                    messages.LeftDown, messages.LeftUp, messages.OtherButtons,
                    messages.SystemKeys, messages.OutsideTargetInput, messages.Overflow,
                    cursor_before = cursorBefore,
                    cursor_after = cursorAfter,
                    parent_input_messages_expected = true,
                    observation_scope = "own_ui_thread_actual_control_window_and_descendants"
                });
                messages.Dispose();
            }
            if (latest is not null)
            {
                evidence.Event("window_input_child_observation", new
                {
                    sequence = latest.Sequence, moves = latest.MoveCount,
                    left_down = latest.LeftDownCount, left_up = latest.LeftUpCount,
                    key_down = latest.KeyDownCount, key_up = latest.KeyUpCount,
                    characters = latest.CharacterCount, unexpected_characters = latest.UnexpectedCharacters,
                    repeated_characters = latest.RepeatedCharacters, overflow_characters = latest.OverflowCharacters,
                    unexpected_buttons = latest.UnexpectedButtons, system_characters = latest.SystemCharacters,
                    latest.Shown, latest.WindowVisible, latest.ForegroundOwn, latest.FocusOwn,
                    latest.DesktopInputQuerySucceeded, latest.DesktopReceivesInput,
                    latest.VirtualScreen, latest.PhysicalClientScreen, latest.PhysicalEqualsLogical,
                    failure_stage = latest.FailureStage, failure_hresult = latest.FailureHresult
                });
            }
            evidence.WindowInputVerified = complete && evidence.WindowInputCleanupVerified == true;
            if (complete && evidence.WindowInputCleanupVerified != true)
                throw new ExperimentFailure("window_input_release_cleanup_unverified");
        }

        evidence.Event("window_input_verified", new
        {
            characters = 8, key_down = 8, key_up = 8, left_down = 1, left_up = 1,
            scope = "standard_parent_window_input_to_distinct_child_witness",
            native_viewer_tested = false,
            direct_input_channel_tested = false,
            physical_device_isolation = false
        });
    }

    private static void RequireGeometry(InputObservation current, InputObservation baseline)
    {
        if (current.VirtualScreen != baseline.VirtualScreen ||
            current.PhysicalClientScreen != baseline.PhysicalClientScreen ||
            current.ClientScreen != baseline.ClientScreen || !current.PhysicalEqualsLogical || current.MonitorCount != 1)
            throw new ExperimentFailure("window_input_child_geometry_changed");
    }

    private static void RequireHealthy(InputObservation value)
    {
        if (value.FailureStage is not null) throw new ExperimentFailure(value.FailureStage, value.FailureHresult);
        if (value.Closed || !value.Shown || !value.WindowVisible || !value.ForegroundOwn || !value.FocusOwn ||
            !value.DesktopInputQuerySucceeded || !value.DesktopReceivesInput)
            throw new ExperimentFailure("window_input_witness_ui_not_ready");
        if (value.CharacterCount is < 0 or > 8 || value.KeyDownCount is < 0 or > 8 || value.KeyUpCount is < 0 or > 8 ||
            value.LeftDownCount is < 0 or > 1 || value.LeftUpCount is < 0 or > 1 ||
            value.UnexpectedCharacters != 0 || value.RepeatedCharacters != 0 || value.OverflowCharacters != 0 ||
            value.UnexpectedButtons != 0 || value.SystemCharacters != 0)
            throw new ExperimentFailure("window_input_witness_unexpected_message");
    }
}

internal sealed class WindowInputTarget
{
    private enum OwnerRole { Parent, Host, Control, Focus, PointHit }
    private enum ValidationPhase { Constructor, BeforeFocus, AfterFocus, Runtime, Point }

    private readonly Form parent;
    private readonly RdpHost host;
    private readonly object control;
    private readonly Action<string, object?> record;
    private readonly IOleInPlaceObject oleWindow;
    private readonly uint thread = InputNative.GetCurrentThreadId();
    private readonly uint process = checked((uint)Environment.ProcessId);
    private readonly IntPtr parentWindow;
    private readonly IntPtr hostWindow;
    private readonly IntPtr layout;
    private bool focusSelected;
    private bool ownerFailureRecorded;
    internal IntPtr Window { get; }
    internal InputRectangle ClientRectangle { get; }
    internal Rectangle Desktop { get; }

    internal WindowInputTarget(Form parent, RdpHost host, object control, Action<string, object?> record)
    {
        this.parent = parent;
        this.host = host;
        this.control = control;
        this.record = record;
        if (parent.IsDisposed || host.IsDisposed || !parent.IsHandleCreated || !host.IsHandleCreated)
            throw new ExperimentFailure("window_input_parent_not_ready");
        parentWindow = parent.Handle;
        hostWindow = host.Handle;
        oleWindow = control as IOleInPlaceObject ?? throw new ExperimentFailure("window_input_ole_window_unavailable");
        int result = oleWindow.GetWindow(out IntPtr window);
        if (result != 0 || window == IntPtr.Zero)
            throw new ExperimentFailure("window_input_ole_window_query_failed", result);
        Window = window;
        uint actualThread = WindowInputNative.GetWindowThreadProcessId(Window, out uint actualProcess);
        bool rectangleAvailable = WindowInputNative.GetClientRect(Window, out WindowInputNative.Rectangle bounds);
        record("window_input_target_resolved", new
        {
            ole_window_hresult = result,
            control_inside_host = Own(Window, hostWindow),
            control_process_is_own = actualProcess == process,
            control_thread_is_own = actualThread == thread,
            parent_is_foreground = InputNative.GetForegroundWindow() == parentWindow,
            focus_inside_control = Own(InputNative.GetFocus(), Window),
            control_visible = InputNative.IsWindowVisible(Window),
            native_rectangle_available = rectangleAvailable,
            native_client_width = rectangleAvailable ? bounds.Right - bounds.Left : (int?)null,
            native_client_height = rectangleAvailable ? bounds.Bottom - bounds.Top : (int?)null,
            host_client = InputRectangle.From(host.RectangleToScreen(host.ClientRectangle))
        });
        ClientRectangle = NativeRectangle();
        Desktop = SystemInformation.VirtualScreen;
        layout = WindowInputNative.GetKeyboardLayout(0);
        if (layout == IntPtr.Zero || Screen.AllScreens.Length != 1 || Desktop.X != 0 || Desktop.Y != 0 ||
            Desktop.Width is <= 0 or > 4096 || Desktop.Height is <= 0 or > 4096 ||
            !Desktop.Contains(ClientRectangle.Rectangle))
            throw new ExperimentFailure("window_input_parent_geometry_not_supported");
        object advanced = Dispatch.Get(control, "AdvancedSettings9") ??
            throw new ExperimentFailure("window_input_advanced_settings_unavailable");
        if (Dispatch.Get(advanced, "SmartSizing") is not bool smartSizing || smartSizing)
            throw new ExperimentFailure("window_input_smart_sizing_not_supported");
        Require(requireFocus: false, ValidationPhase.Constructor);
    }

    internal void SelectOwnFocusOnce()
    {
        if (focusSelected) throw new ExperimentFailure("window_input_focus_request_repeated");
        Require(requireFocus: false, ValidationPhase.BeforeFocus);
        focusSelected = true;
        WindowInputNative.SetFocus(Window);
        Require(requireFocus: true, ValidationPhase.AfterFocus);
    }

    internal void Require(bool requireFocus = true) => Require(requireFocus, ValidationPhase.Runtime);

    private void Require(bool requireFocus, ValidationPhase phase)
    {
        if (InputNative.GetCurrentThreadId() != thread || parent.IsDisposed || host.IsDisposed ||
            !parent.IsHandleCreated || !host.IsHandleCreated || parent.Handle != parentWindow || host.Handle != hostWindow ||
            parent.InvokeRequired || !InputNative.IsChild(parentWindow, hostWindow) ||
            Window == parentWindow || !Own(Window, hostWindow) ||
            !InputNative.IsWindowVisible(parentWindow) || !InputNative.IsWindowVisible(Window) ||
            !WindowInputNative.IsWindowEnabled(Window) || WindowInputNative.IsIconic(parentWindow) ||
            InputNative.GetForegroundWindow() != parentWindow)
            throw new ExperimentFailure("window_input_target_ownership_or_foreground_changed");
        RequireOwnThread(parentWindow, OwnerRole.Parent, phase);
        RequireOwnThread(hostWindow, OwnerRole.Host, phase);
        RequireOwnThread(Window, OwnerRole.Control, phase);
        int result = oleWindow.GetWindow(out IntPtr actual);
        if (result != 0 || actual != Window)
            throw new ExperimentFailure("window_input_control_window_changed", result);
        if (Convert.ToInt32(Dispatch.Get(control, "Connected"), CultureInfo.InvariantCulture) != 1)
            throw new ExperimentFailure("window_input_control_disconnected");
        if (requireFocus)
        {
            IntPtr focus = InputNative.GetFocus();
            if (!Own(focus, Window)) throw new ExperimentFailure("window_input_focus_left_own_control");
            RequireOwnThread(focus, OwnerRole.Focus, phase);
        }
        if (NativeRectangle() != ClientRectangle ||
            InputRectangle.From(host.RectangleToScreen(host.ClientRectangle)) != ClientRectangle ||
            SystemInformation.VirtualScreen != Desktop || Screen.AllScreens.Length != 1 ||
            Convert.ToInt32(Dispatch.Get(control, "DesktopWidth"), CultureInfo.InvariantCulture) != ClientRectangle.Width ||
            Convert.ToInt32(Dispatch.Get(control, "DesktopHeight"), CultureInfo.InvariantCulture) != ClientRectangle.Height ||
            WindowInputNative.GetKeyboardLayout(0) != layout)
            throw new ExperimentFailure("window_input_parent_geometry_or_layout_changed");
        bool query = InputNative.DesktopInput(InputNative.GetThreadDesktop(thread), 6,
            out int receivesInput, sizeof(int), out uint needed);
        if (!query || needed != sizeof(int) || receivesInput == 0)
            throw new ExperimentFailure("window_input_parent_not_on_input_desktop", query ? 0 : Marshal.GetLastWin32Error());
    }

    internal void RequirePoint(InputPoint point, bool requireCursor)
    {
        Require(requireFocus: true, ValidationPhase.Point);
        if (!ClientRectangle.Rectangle.Contains(point.X, point.Y))
            throw new ExperimentFailure("window_input_point_outside_control");
        IntPtr hit = InputNative.WindowFromPoint(new InputNative.Point(point.X, point.Y));
        if (!Own(hit, Window)) throw new ExperimentFailure("window_input_point_not_over_control");
        RequireOwnThread(hit, OwnerRole.PointHit, ValidationPhase.Point);
        if (requireCursor && WindowInputNative.Cursor() != point)
            throw new ExperimentFailure("window_input_parent_cursor_changed");
    }

    internal ushort DigitScanCode(char digit)
    {
        if (digit is < '0' or > '9') throw new ExperimentFailure("window_input_digit_required");
        short key = WindowInputNative.VkKeyScanExW(digit, layout);
        if (key == -1 || (key & 0xff00) != 0 || (key & 0xff) != digit)
            throw new ExperimentFailure("window_input_digit_layout_requires_modifier");
        uint scan = WindowInputNative.MapVirtualKeyExW(checked((uint)digit), 4 /* MAPVK_VK_TO_VSC_EX */, layout);
        if (scan is 0 or > 0xff) throw new ExperimentFailure("window_input_digit_scancode_not_supported");
        return checked((ushort)scan);
    }

    private InputRectangle NativeRectangle()
    {
        if (!WindowInputNative.GetClientRect(Window, out WindowInputNative.Rectangle bounds) ||
            bounds.Left != 0 || bounds.Top != 0 || bounds.Right is <= 0 or > 4096 || bounds.Bottom is <= 0 or > 4096)
            throw new ExperimentFailure("window_input_control_rectangle_invalid", Marshal.GetLastWin32Error());
        InputNative.Point first = new(0, 0), last = new(bounds.Right, bounds.Bottom);
        if (!InputNative.ClientToScreen(Window, ref first) || !InputNative.ClientToScreen(Window, ref last))
            throw new ExperimentFailure("window_input_coordinate_conversion_failed", Marshal.GetLastWin32Error());
        InputNative.Point physicalFirst = first, physicalLast = last;
        if (!InputNative.LogicalToPhysicalPointForPerMonitorDPI(Window, ref physicalFirst) ||
            !InputNative.LogicalToPhysicalPointForPerMonitorDPI(Window, ref physicalLast) ||
            physicalFirst.Value != first.Value || physicalLast.Value != last.Value ||
            last.X - first.X != bounds.Right || last.Y - first.Y != bounds.Bottom)
            throw new ExperimentFailure("window_input_scaled_coordinates_not_supported");
        return new(first.X, first.Y, bounds.Right, bounds.Bottom);
    }

    private void RequireOwnThread(IntPtr window, OwnerRole role, ValidationPhase phase)
    {
        uint actualThread = WindowInputNative.GetWindowThreadProcessId(window, out uint actualProcess);
        if (actualThread != thread || actualProcess != process)
        {
            int? queryError = actualThread == 0 ? Marshal.GetLastPInvokeError() : null;
            RecordOwnerFailure(window, actualThread, actualProcess, queryError, role, phase);
            throw new ExperimentFailure("window_input_target_thread_or_process_changed");
        }
    }

    private void RecordOwnerFailure(IntPtr window, uint actualThread, uint actualProcess, int? queryError,
        OwnerRole role, ValidationPhase phase)
    {
        // One failure record per target. Successful polling and input checks
        // add no observations or allocations; no raw HWND, PID or TID is logged.
        if (ownerFailureRecorded) return;
        ownerFailureRecorded = true;
        try
        {
            record("window_input_target_owner_mismatch", new
            {
                role = role.ToString(),
                validation_phase = phase.ToString(),
                owner_query_succeeded = actualThread != 0,
                owner_query_error = queryError,
                owner_thread_is_expected = actualThread != 0 ? actualThread == thread : (bool?)null,
                owner_process_is_own = actualThread != 0 ? actualProcess == process : (bool?)null,
                current_thread_is_expected = InputNative.GetCurrentThreadId() == thread,
                window_nonzero = window != IntPtr.Zero,
                window_is_parent = window == parentWindow,
                window_is_host = window == hostWindow,
                window_is_control = window == Window,
                window_inside_host = Own(window, hostWindow),
                window_inside_control = Own(window, Window),
                focus_request_made = focusSelected
            });
        }
        catch (Exception)
        {
            // A diagnostic failure must not replace the original ownership
            // failure, trigger another focus request, or retry any input.
        }
    }

    internal static bool Own(IntPtr window, IntPtr parent) => window != IntPtr.Zero &&
        (window == parent || InputNative.IsChild(parent, window));

    // Standard SDK IOleInPlaceObject, whose first two methods are IOleWindow.
    // This is the same interface used by the native OLE host, with no inferred
    // ActiveX/private input interface.
    // The RCW is borrowed from AxHost; this helper never final-releases it.
    [ComImport, Guid("00000113-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IOleInPlaceObject
    {
        [PreserveSig] int GetWindow(out IntPtr window);
        [PreserveSig] int ContextSensitiveHelp([MarshalAs(UnmanagedType.Bool)] bool enterMode);
        [PreserveSig] int InPlaceDeactivate();
        [PreserveSig] int UIDeactivate();
        [PreserveSig] int SetObjectRects(in WindowInputNative.Rectangle position, in WindowInputNative.Rectangle clip);
        [PreserveSig] int ReactivateAndUndo();
    }
}

internal sealed class WindowInputEmitter
{
    private readonly WindowInputTarget target;
    private readonly Action requireTarget;
    private readonly WindowInputNative.Input[] batch = new WindowInputNative.Input[2];
    private readonly byte[] keyboard = new byte[256];
    private readonly bool[] submittedKeys = new bool[256];
    private readonly int inputSize;
    private ushort pendingScan;
    private InputPoint? lastPoint;
    private bool cleanupAttempted;
    private bool submittedButton;
    private bool cleanupVerified;
    internal bool KeyPending { get; private set; }
    internal bool ButtonPending { get; private set; }
    internal bool SubmissionUnknown { get; private set; }
    internal int Calls { get; private set; }
    internal int Requested { get; private set; }
    internal int Inserted { get; private set; }
    internal int CleanupCalls { get; private set; }
    internal int CleanupInserted { get; private set; }
    internal int CleanupObservations { get; private set; }

    internal WindowInputEmitter(WindowInputTarget target, Action requireTarget)
    {
        this.target = target;
        this.requireTarget = requireTarget;
        inputSize = Marshal.SizeOf<WindowInputNative.Input>();
        if (inputSize != (IntPtr.Size == 8 ? 40 : 28) ||
            Marshal.OffsetOf<WindowInputNative.Input>(nameof(WindowInputNative.Input.Data)).ToInt32() != (IntPtr.Size == 8 ? 8 : 4))
            throw new ExperimentFailure("window_input_sdk_input_layout_invalid");
    }

    internal void Move(InputPoint point)
    {
        Before(point, requireCursor: false);
        int x = Normalize(point.X - target.Desktop.X, target.Desktop.Width);
        int y = Normalize(point.Y - target.Desktop.Y, target.Desktop.Height);
        batch[0] = WindowInputNative.Mouse(0x0001 | 0x8000 | 0x4000, x, y);
        uint inserted = Submit(1);
        if (inserted != 1) throw new ExperimentFailure("window_input_move_submission_failed", Marshal.GetLastPInvokeError());
        lastPoint = point;
    }

    internal void LeftClick(InputPoint point)
    {
        Before(point, requireCursor: true);
        batch[0] = WindowInputNative.Mouse(0x0002);
        batch[1] = WindowInputNative.Mouse(0x0004);
        uint inserted = Submit(2);
        ButtonPending = inserted == 1;
        if (inserted != 0) submittedButton = true;
        if (inserted != 2) throw new ExperimentFailure("window_input_click_submission_incomplete", Marshal.GetLastPInvokeError());
    }

    internal void KeyPair(ushort scan, char digit, InputPoint point)
    {
        Before(point, requireCursor: true);
        if (scan != target.DigitScanCode(digit)) throw new ExperimentFailure("window_input_scancode_changed");
        batch[0] = WindowInputNative.Key(scan, up: false);
        batch[1] = WindowInputNative.Key(scan, up: true);
        uint inserted = Submit(2);
        KeyPending = inserted == 1;
        if (KeyPending) pendingScan = scan;
        if (inserted != 0) submittedKeys[digit] = true;
        if (inserted != 2) throw new ExperimentFailure("window_input_key_submission_incomplete", Marshal.GetLastPInvokeError());
    }

    internal void RequireReleased()
    {
        if (SubmissionUnknown || KeyPending || ButtonPending || !OwnInputsReleased())
            throw new ExperimentFailure("window_input_own_release_unconfirmed");
    }

    internal async Task<bool> ReleasePending(Action<string, object?> record)
    {
        if (cleanupAttempted) return cleanupVerified;
        cleanupAttempted = true;
        // A thrown interop call supplies no returned insertion count. It never
        // creates an owned-down receipt or authorizes an assumed release.
        if (SubmissionUnknown) return false;
        try
        {
            if (KeyPending)
            {
                requireTarget();
                target.RequirePoint(lastPoint ?? throw new ExperimentFailure("window_input_cleanup_point_missing"), true);
                batch[0] = WindowInputNative.Key(pendingScan, up: true);
                CleanupCalls++;
                uint inserted = WindowInputNative.SendInput(1, batch, inputSize);
                CleanupInserted += checked((int)inserted);
                if (inserted == 1) KeyPending = false;
            }
            if (ButtonPending)
            {
                requireTarget();
                target.RequirePoint(lastPoint ?? throw new ExperimentFailure("window_input_cleanup_point_missing"), true);
                batch[0] = WindowInputNative.Mouse(0x0004);
                CleanupCalls++;
                uint inserted = WindowInputNative.SendInput(1, batch, inputSize);
                CleanupInserted += checked((int)inserted);
                if (inserted == 1) ButtonPending = false;
            }
            if (KeyPending || ButtonPending) return false;
            if (!submittedButton && !submittedKeys.Any(value => value))
            {
                cleanupVerified = true;
                return true;
            }
            // Submission is not delivery. Let our UI queue process accepted
            // releases, then observe only input for which we kept an own-send
            // receipt. There is no replay of a down event or blanket key reset.
            for (int attempt = 0; attempt < 20; attempt++)
            {
                await Task.Delay(25);
                requireTarget();
                CleanupObservations++;
                if (OwnInputsReleased())
                {
                    cleanupVerified = true;
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            record("window_input_cleanup_failed", new
            {
                exception_type = ex.GetType().Name,
                stage = ex is ExperimentFailure failure ? failure.Stage : null,
                code = ex is ExperimentFailure known ? known.Code : ex.HResult
            });
            return false;
        }
        return false;
    }

    private bool OwnInputsReleased()
    {
        if (!WindowInputNative.GetKeyboardState(keyboard)) return false;
        if (submittedButton && ((keyboard[1] & 0x80) != 0 || (WindowInputNative.GetAsyncKeyState(1) & 0x8000) != 0))
            return false;
        for (int i = 0; i < submittedKeys.Length; i++)
            if (submittedKeys[i] && ((keyboard[i] & 0x80) != 0 || (WindowInputNative.GetAsyncKeyState(i) & 0x8000) != 0))
                return false;
        return true;
    }

    private void Before(InputPoint point, bool requireCursor)
    {
        if (cleanupAttempted || SubmissionUnknown || KeyPending || ButtonPending)
            throw new ExperimentFailure("window_input_pending_release_or_closed");
        requireTarget();
        target.RequirePoint(point, requireCursor);
        if (!WindowInputNative.GetKeyboardState(keyboard))
            throw new ExperimentFailure("window_input_keyboard_state_unavailable", Marshal.GetLastWin32Error());
        for (int i = 1; i < keyboard.Length; i++)
            if ((keyboard[i] & 0x80) != 0 || (WindowInputNative.GetAsyncKeyState(i) & 0x8000) != 0)
                throw new ExperimentFailure("window_input_preexisting_pressed_input");
    }

    private uint Submit(uint count)
    {
        Calls++;
        Requested += checked((int)count);
        Marshal.SetLastPInvokeError(0);
        uint inserted;
        try
        {
            inserted = WindowInputNative.SendInput(count, batch, inputSize);
        }
        catch
        {
            SubmissionUnknown = true;
            throw;
        }
        if (inserted > count)
        {
            SubmissionUnknown = true;
            throw new ExperimentFailure("window_input_submission_count_invalid");
        }
        Inserted += checked((int)inserted);
        return inserted;
    }

    private static int Normalize(int pixel, int extent)
    {
        if (extent is <= 0 or > 4096 || pixel < 0 || pixel >= extent)
            throw new ExperimentFailure("window_input_absolute_coordinate_invalid");
        // Choose the centre of the pixel's normalized interval. The actual
        // parent cursor and independent child message must still match exactly.
        return checked((int)(((2L * pixel + 1) * 65536) / (2L * extent)));
    }
}

internal sealed class WindowMessageObservation : IMessageFilter, IDisposable
{
    private readonly IntPtr parent;
    private readonly IntPtr target;
    private bool attached = true;
    private int total;
    internal int KeyDown { get; private set; }
    internal int KeyUp { get; private set; }
    internal int Characters { get; private set; }
    internal int LeftDown { get; private set; }
    internal int LeftUp { get; private set; }
    internal int OtherButtons { get; private set; }
    internal int SystemKeys { get; private set; }
    internal int OutsideTargetInput { get; private set; }
    internal bool Overflow { get; private set; }

    internal WindowMessageObservation(IntPtr parent, IntPtr target)
    {
        this.parent = parent;
        this.target = target;
        Application.AddMessageFilter(this);
    }

    public bool PreFilterMessage(ref Message message)
    {
        if (!InputNative.KeyboardMessage(message.Msg) && !InputNative.ButtonMessage(message.Msg)) return false;
        if (!WindowInputTarget.Own(message.HWnd, parent)) return false;
        if (++total > 128) { Overflow = true; return false; }
        if (!WindowInputTarget.Own(message.HWnd, target)) { OutsideTargetInput++; return false; }
        switch (message.Msg)
        {
            case 0x0100: KeyDown++; break;
            case 0x0101: KeyUp++; break;
            case 0x0102: case 0x0109: Characters++; break;
            case 0x0104: case 0x0105: case 0x0106: case 0x0107: SystemKeys++; break;
            case 0x0201: LeftDown++; break;
            case 0x0202: LeftUp++; break;
            default:
                if (InputNative.ButtonMessage(message.Msg)) OtherButtons++;
                break;
        }
        return false;
    }

    public void Dispose()
    {
        if (!attached) return;
        attached = false;
        Application.RemoveMessageFilter(this);
    }
}

internal static class WindowInputNative
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Rectangle { internal int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct MouseInput
    {
        internal int X, Y;
        internal uint Data, Flags, Time;
        internal UIntPtr Extra;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct KeyboardInput
    {
        internal ushort VirtualKey, Scan;
        internal uint Flags, Time;
        internal UIntPtr Extra;
    }
    [StructLayout(LayoutKind.Explicit)]
    internal struct InputData
    {
        [FieldOffset(0)] internal MouseInput Mouse;
        [FieldOffset(0)] internal KeyboardInput Keyboard;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct Input
    {
        internal uint Type;
        internal InputData Data;
    }

    internal static Input Mouse(uint flags, int x = 0, int y = 0) => new()
    {
        Type = 0,
        Data = new InputData { Mouse = new MouseInput { X = x, Y = y, Flags = flags } }
    };
    internal static Input Key(ushort scan, bool up) => new()
    {
        Type = 1,
        Data = new InputData { Keyboard = new KeyboardInput { Scan = scan, Flags = 0x0008U | (up ? 0x0002U : 0) } }
    };
    internal static InputPoint Cursor()
    {
        if (!InputNative.GetCursorPos(out InputNative.Point point))
            throw new ExperimentFailure("window_input_parent_cursor_unavailable", Marshal.GetLastWin32Error());
        return point.Value;
    }

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern uint SendInput(uint count, [In] Input[] inputs, int size);
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern short GetAsyncKeyState(int key);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetKeyboardState([Out] byte[] state);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern IntPtr SetFocus(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindowEnabled(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetClientRect(IntPtr window, out Rectangle bounds);
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetKeyboardLayout(uint thread);
    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    internal static extern short VkKeyScanExW(char character, IntPtr layout);
    [DllImport("user32.dll", ExactSpelling = true)]
    internal static extern uint MapVirtualKeyExW(uint code, uint mapType, IntPtr layout);
}
