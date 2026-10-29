using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SessionContractExperiment;

// Additional keyboard acceptance after the independently accepted normal
// window path. An own decoy holds the parent's foreground and keyboard focus.
// The child learns the challenge only from its actual keyboard messages.
internal static class BackgroundKeyboardExperiment
{
    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr window);
    internal static async Task Run(Form parent, Control host, object control, Evidence evidence,
        string identityFile, string nonce, uint session, string digest,
        Action requireOwnership, TimeSpan remaining)
    {
        if (!evidence.SendKeysRequested || !evidence.WindowInputVerified ||
            evidence.WindowInputCleanupVerified != true || !evidence.FrameChallengeVerified ||
            !evidence.DifferentAccountVerified || evidence.ChildMatchesCreatedAccountSid != true)
            throw new ExperimentFailure("sendkeys_prior_frame_window_identity_gate_failed");
        if (remaining < TimeSpan.FromSeconds(10)) throw new ExperimentFailure("sendkeys_budget_unavailable");
        TimeSpan budget = remaining < TimeSpan.FromSeconds(20) ? remaining : TimeSpan.FromSeconds(20);
        Stopwatch elapsed = Stopwatch.StartNew();
        string path = Path.Combine(Path.GetDirectoryName(identityFile)!, "witness-input.json");
        InputObservation? latest = null;
        long sequence = 0;
        bool complete = false;
        bool decoyDestroyed = false;
        IntPtr parentWindow = parent.Handle, hostWindow = host.Handle;
        IntPtr layout = WindowInputNative.GetKeyboardLayout(0);
        ValidatedSendKeys? sink = null;
        ForegroundWatch? watch = null;
        ParentInputProbe? parentProbe = null, decoyProbe = null;
        using Form decoy = new() { Text = "Owned keyboard isolation observer", ShowInTaskbar = false,
            StartPosition = FormStartPosition.Manual, Location = new Point(parent.Left + 24, parent.Top + 24),
            ClientSize = new Size(280, 100), FormBorderStyle = FormBorderStyle.FixedToolWindow,
            TopMost = true, MaximizeBox = false, MinimizeBox = false, BackColor = Color.DarkSlateGray };
        IntPtr decoyWindow = IntPtr.Zero;
        try
        {
            requireOwnership();
            sink = new ValidatedSendKeys(control, evidence.Event);
            // Own-process activation, once. No call to activate the RDP host
            // is permitted after this decoy has become the test foreground.
            decoy.Show(parent);
            decoy.Activate();
            decoyWindow = decoy.Handle;
            parentProbe = new ParentInputProbe(parent);
            decoyProbe = new ParentInputProbe(decoy);
            watch = new ForegroundWatch(decoyWindow);
            watch.Install();

            void Check()
            {
                if (elapsed.Elapsed >= budget) throw new ExperimentFailure("sendkeys_timeout");
                requireOwnership();
                if (parent.IsDisposed || host.IsDisposed || parent.Handle != parentWindow || host.Handle != hostWindow ||
                    decoy.IsDisposed || !decoy.IsHandleCreated || decoy.Handle != decoyWindow ||
                    !decoy.Visible || !decoy.Enabled || decoy.WindowState == FormWindowState.Minimized)
                    throw new ExperimentFailure("sendkeys_own_window_identity_changed");
                if (InputNative.GetForegroundWindow() != decoyWindow ||
                    !WindowInputTarget.Own(InputNative.GetFocus(), decoyWindow) ||
                    WindowInputTarget.Own(InputNative.GetFocus(), hostWindow) ||
                    WindowInputNative.GetKeyboardLayout(0) != layout)
                    throw new ExperimentFailure("sendkeys_decoy_foreground_or_focus_lost");
                uint actualThread = WindowInputNative.GetWindowThreadProcessId(decoyWindow, out uint process);
                if (actualThread != InputNative.GetCurrentThreadId() || process != (uint)Environment.ProcessId)
                    throw new ExperimentFailure("sendkeys_decoy_owner_changed");
                watch.RequireHealthy();
                parentProbe.Check();
                decoyProbe.Check();
            }

            InputObservation Read()
            {
                Check();
                InputObservation report = InputReport.Read(path, nonce, session, digest);
                if (report.Sequence < sequence) throw new ExperimentFailure("sendkeys_child_sequence_regressed");
                sequence = report.Sequence;
                latest = report;
                RequireHealthy(report);
                return report;
            }

            async Task<InputObservation> Wait(Func<InputObservation, bool> ready)
            {
                for (;;)
                {
                    InputObservation report = Read();
                    if (ready(report)) return report;
                    await Task.Delay(60);
                }
            }

            InputObservation before = Read();
            InputObservation baseline = await Wait(r => r.Sequence > before.Sequence);
            RequireBaseline(baseline);
            string challenge = string.Create(8, 0, (text, _) =>
            {
                for (int i = 0; i < text.Length; i++) text[i] = (char)('0' + RandomNumberGenerator.GetInt32(10));
            });
            string expected = baseline.ReceivedHex + challenge;
            evidence.Event("sendkeys_background_baseline", new { baseline_sequence = baseline.Sequence,
                baseline_characters = baseline.CharacterCount, baseline_keys_down = baseline.KeyDownCount,
                baseline_keys_up = baseline.KeyUpCount, expected_new_characters = 8,
                foreground_is_owned_decoy = true, focus_is_owned_decoy = true,
                original_rdp_host_has_focus = false, parent_cursor_unchanged = true,
                foreground_and_focus_event_observers_installed = true });
            Check();
            sink.SendEightDigits(challenge, layout);
            Check();
            evidence.Event("sendkeys_call_returned", new { calls = sink.Calls, entries = sink.Entries,
                hresult = sink.Hresult, delivery_proven_by_return = false });
            InputObservation received = await Wait(r => r.CharacterCount >= 16 && r.KeyDownCount >= 16 && r.KeyUpCount >= 16);
            RequireFinal(received, baseline, expected);
            Stopwatch quiet = Stopwatch.StartNew();
            InputObservation final = received;
            while (quiet.Elapsed < TimeSpan.FromSeconds(1))
            {
                await Task.Delay(60);
                final = Read();
                RequireFinal(final, baseline, expected);
            }
            long quietEnd = final.Sequence;
            final = await Wait(r => { RequireFinal(r, baseline, expected); return r.Sequence > quietEnd; });
            RequireFinal(final, baseline, expected);
            Check();
            complete = true;
            evidence.Event("sendkeys_background_delivery_observed", new { new_characters = 8,
                new_key_down = 8, new_key_up = 8, new_mouse_buttons = 0,
                baseline_sequence = baseline.Sequence, final_sequence = final.Sequence,
                nonce_and_identity_verified = true, challenge_supplied_out_of_band = false,
                own_parent_and_decoy_ui_keyboard_messages = 0,
                observation_scope = "own_ui_queue_plus_foreground_and_focus_events_on_parent_desktop",
                physical_keyboard_isolation = false, background_mouse_tested = false });
        }
        finally
        {
            bool watchRemoved = watch is null, released = sink is null;
            Exception? cleanupError = null;
            try { if (watch is not null) watchRemoved = watch.Stop(); }
            catch (Exception error) { cleanupError = error; }
            try { if (sink is not null) { sink.Dispose(); released = sink.Released; } }
            catch (Exception error) { cleanupError ??= error; }
            bool parentUnchanged = parentProbe is not null && decoyProbe is not null &&
                parentProbe.KeyboardCount == 0 && parentProbe.ButtonCount == 0 && parentProbe.CursorUnchanged &&
                decoyProbe.KeyboardCount == 0 && decoyProbe.ButtonCount == 0 && decoyProbe.CursorUnchanged;
            parentProbe?.Dispose(); decoyProbe?.Dispose();
            try
            {
                decoy.Close(); decoy.Dispose();
                decoyDestroyed = decoyWindow == IntPtr.Zero || !IsWindow(decoyWindow);
            }
            catch (Exception error) { cleanupError ??= error; }
            evidence.SendKeysCleanupVerified = watchRemoved && released && decoyDestroyed && cleanupError is null;
            evidence.SendKeysVerified = TerminalAccepted(complete, parentUnchanged, evidence.SendKeysCleanupVerified == true, watch);
            evidence.Event("sendkeys_result", new { verified = evidence.SendKeysVerified,
                calls = sink?.Calls ?? 0, entries = sink?.Entries ?? 0, hresult = sink?.Hresult,
                parent_keyboard_messages = parentProbe?.KeyboardCount, decoy_keyboard_messages = decoyProbe?.KeyboardCount,
                parent_button_messages = parentProbe?.ButtonCount, decoy_button_messages = decoyProbe?.ButtonCount,
                parent_cursor_unchanged = parentUnchanged,
                foreground_events = watch?.ForegroundEvents ?? 0, focus_events = watch?.FocusEvents ?? 0,
                foreign_foreground_or_focus_seen = watch?.WrongWindowSeen ?? false,
                observer_removed = watchRemoved, interface_released = released, decoy_destroyed = decoyDestroyed,
                local_cleanup_verified = evidence.SendKeysCleanupVerified,
                final_child_sequence = latest?.Sequence, final_characters = latest?.CharacterCount,
                final_key_down = latest?.KeyDownCount, final_key_up = latest?.KeyUpCount,
                full_native_viewer_executed = false, physical_device_isolation = false });
            if (cleanupError is not null) evidence.Error("sendkeys_cleanup_error", cleanupError);
            if (complete && !evidence.SendKeysVerified)
                throw new ExperimentFailure("sendkeys_final_observation_or_cleanup_failed");
        }
    }

    internal static bool TerminalAccepted(bool complete, bool parentUnchanged, bool localCleanup, ForegroundWatch? watch) =>
        complete && parentUnchanged && localCleanup && watch is not null && watch.StoppedSuccessfully && !watch.WrongWindowSeen;

    internal static void RequireHealthy(InputObservation report)
    {
        if (report.FailureStage is not null) throw new ExperimentFailure(report.FailureStage, report.FailureHresult);
        if (!report.Shown || report.Closed || !report.WindowVisible || !report.ForegroundOwn || !report.FocusOwn ||
            !report.DesktopInputQuerySucceeded || !report.DesktopReceivesInput || report.CharacterLimit != 16 ||
            report.CharacterCount is < 8 or > 16 || report.KeyDownCount is < 8 or > 16 || report.KeyUpCount is < 8 or > 16 ||
            report.UnexpectedCharacters != 0 || report.RepeatedCharacters != 0 || report.OverflowCharacters != 0 ||
            report.UnexpectedButtons != 0 || report.SystemCharacters != 0 || report.LeftDownCount != 1 || report.LeftUpCount != 1)
            throw new ExperimentFailure("sendkeys_child_ui_or_input_unhealthy");
    }

    internal static void RequireBaseline(InputObservation value)
    {
        RequireHealthy(value);
        if (value.CharacterCount != 8 || value.KeyDownCount != 8 || value.KeyUpCount != 8 || value.ReceivedHex.Length != 8 || !value.CursorQuerySucceeded)
            throw new ExperimentFailure("sendkeys_child_baseline_invalid");
    }

    internal static void RequireFinal(InputObservation value, InputObservation baseline, string expected)
    {
        RequireHealthy(value);
        if (value.Sequence <= baseline.Sequence || value.CharacterCount != 16 || value.KeyDownCount != 16 ||
            value.KeyUpCount != 16 || value.ReceivedHex != expected || expected.Length != 16 ||
            value.LeftDownPoint != baseline.LeftDownPoint || value.LeftUpPoint != baseline.LeftUpPoint ||
            value.VirtualScreen != baseline.VirtualScreen || value.PhysicalClientScreen != baseline.PhysicalClientScreen ||
            value.ClientScreen != baseline.ClientScreen || value.MonitorCount != baseline.MonitorCount ||
            value.PhysicalEqualsLogical != baseline.PhysicalEqualsLogical ||
            !value.CursorQuerySucceeded || value.Cursor != baseline.Cursor)
            throw new ExperimentFailure("sendkeys_child_receipt_mismatch");
    }
}

// The foreground hook must also observe a transient switch and return during
// the COM call. Callback records only counters/ownership; no titles or text.
// Out-of-context callbacks are delivered on this installing UI thread.
internal sealed class ForegroundWatch
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void Callback(IntPtr hook, uint kind, IntPtr window, int objectId, int childId, uint thread, uint time);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWinEventHook(uint first, uint last, IntPtr module, Callback callback,
        uint process, uint thread, uint flags);
    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWinEvent(IntPtr hook);
    // Retain the inert callback after unhook until process exit, including the
    // failure case. A late callback cannot reach a collected delegate.
    private static readonly List<ForegroundWatch> Roots = new();
    private readonly IntPtr window;
    private readonly uint ownerThread = InputNative.GetCurrentThreadId();
    private readonly Callback callback;
    private IntPtr foreground, focus;
    private bool armed = true;
    private bool stopped;
    private bool stopResult;
    internal bool WrongWindowSeen { get; private set; }
    internal bool StoppedSuccessfully => stopped && stopResult;
    internal int ForegroundEvents { get; private set; }
    internal int FocusEvents { get; private set; }
    internal ForegroundWatch(IntPtr window)
    {
        this.window = window;
        callback = Observe;
        Roots.Add(this);
    }
    internal void Install()
    {
        if (stopped || foreground != IntPtr.Zero || focus != IntPtr.Zero)
            throw new ExperimentFailure("sendkeys_observer_install_repeated");
        foreground = SetWinEventHook(3, 3, IntPtr.Zero, callback, 0, 0, 0);
        if (foreground == IntPtr.Zero) throw new ExperimentFailure("sendkeys_foreground_observer_failed", Marshal.GetLastWin32Error());
        focus = SetWinEventHook(0x8005, 0x8005, IntPtr.Zero, callback, 0, 0, 0);
        if (focus == IntPtr.Zero) throw new ExperimentFailure("sendkeys_focus_observer_failed", Marshal.GetLastWin32Error());
    }
    private void Observe(IntPtr hook, uint kind, IntPtr target, int objectId, int childId, uint thread, uint time)
    {
        if (!armed) return;
        try
        {
            if (InputNative.GetCurrentThreadId() != ownerThread) { WrongWindowSeen = true; return; }
            if (kind == 3) { ForegroundEvents++; if (target != window) WrongWindowSeen = true; }
            else if (kind == 0x8005)
            {
                FocusEvents++;
                if (!WindowInputTarget.Own(target, window)) WrongWindowSeen = true;
            }
            else WrongWindowSeen = true;
            if (ForegroundEvents + FocusEvents > 64) WrongWindowSeen = true;
        }
        catch { WrongWindowSeen = true; }
    }
    internal void RequireHealthy()
    {
        if (!armed || foreground == IntPtr.Zero || focus == IntPtr.Zero || WrongWindowSeen)
            throw new ExperimentFailure("sendkeys_foreground_or_focus_event_changed");
    }
    internal bool Stop()
    {
        if (stopped) return stopResult;
        stopped = true;
        if (InputNative.GetCurrentThreadId() != ownerThread)
        {
            armed = false;
            WrongWindowSeen = true;
            stopResult = false;
            return false;
        }
        bool success = true;
        try
        {
            // Keep recording through both native unhook calls. A callback
            // delivered during removal remains a sticky terminal failure.
            if (foreground != IntPtr.Zero) { bool removed = UnhookWinEvent(foreground); success &= removed; if (removed) foreground = IntPtr.Zero; }
            if (focus != IntPtr.Zero) { bool removed = UnhookWinEvent(focus); success &= removed; if (removed) focus = IntPtr.Zero; }
            stopResult = success;
            return success;
        }
        finally { armed = false; }
    }
}
