using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SessionContractExperiment;

internal static class DirectInputExperiment
{
    internal static async Task Run(Form parent, object control, Evidence evidence, string witnessIdentityFile,
        string bindingNonce, uint childSession, string identityDigest, Action requireOwnership, TimeSpan remaining)
    {
        // This is an additional optional gate, never an alternative to actual
        // parent-captured pixels or to the independently verified B identity.
        if (!evidence.DirectInputRequested || !evidence.FrameChallengeVerified || !evidence.DifferentAccountVerified ||
            evidence.ChildMatchesCreatedAccountSid != true || !evidence.WitnessInExpectedSession || !evidence.WitnessIdentityMatches)
            throw new ExperimentFailure("direct_input_frame_and_account_gate_not_met");
        if (remaining < TimeSpan.FromSeconds(8)) throw new ExperimentFailure("direct_input_budget_unavailable");
        TimeSpan budget = remaining < TimeSpan.FromSeconds(20) ? remaining : TimeSpan.FromSeconds(20);
        Stopwatch elapsed = Stopwatch.StartNew();
        string path = Path.Combine(Path.GetDirectoryName(witnessIdentityFile)!, "witness-input.json");
        long lastSequence = 0;
        InputObservation? latest = null;
        using ParentInputProbe parentProbe = new(parent);
        try
        {
            void Check()
            {
                if (elapsed.Elapsed >= budget) throw new ExperimentFailure("direct_input_timeout");
                requireOwnership();
                parentProbe.Check();
            }

            InputObservation Read()
            {
                Check();
                InputObservation report = InputReport.Read(path, bindingNonce, childSession, identityDigest);
                if (report.Sequence < lastSequence) throw new ExperimentFailure("input_report_sequence_regressed");
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

            evidence.Event("direct_input_frame_gate_passed");
            InputObservation baseline = await Wait(r => r.Shown);
            // Require a fresh observation after the parent begins monitoring.
            long baselineSequence = baseline.Sequence;
            baseline = await Wait(r => r.Sequence > baselineSequence);
            if (baseline.CharacterCount != 0 || baseline.ReceivedHex.Length != 0 ||
                baseline.LeftDownCount != 0 || baseline.LeftUpCount != 0 ||
                baseline.KeyDownCount != 0 || baseline.KeyUpCount != 0)
                throw new ExperimentFailure("input_witness_baseline_not_empty");
            if (!baseline.FocusOwn) throw new ExperimentFailure("input_witness_focus_not_owned");
            InputRectangle desktop = baseline.VirtualScreen;
            if (baseline.MonitorCount != 1 || desktop.X != 0 || desktop.Y != 0 ||
                desktop.Width is <= 0 or > 4096 || desktop.Height is <= 0 or > 4096 ||
                !baseline.PhysicalEqualsLogical || !desktop.Rectangle.Contains(baseline.PhysicalClientScreen.Rectangle))
                throw new ExperimentFailure("input_geometry_not_supported_by_strict_test");
            if (!baseline.CursorQuerySucceeded) throw new ExperimentFailure("child_input_cursor_unavailable", baseline.CursorError);
            Rectangle safe = baseline.PhysicalClientScreen.Rectangle;
            safe.Inflate(-48, -48);
            if (safe.Width < 64 || safe.Height < 64) throw new ExperimentFailure("input_safe_region_too_small");
            InputPoint target;
            do { target = new(RandomNumberGenerator.GetInt32(safe.Left, safe.Right), RandomNumberGenerator.GetInt32(safe.Top, safe.Bottom)); }
            while (target == baseline.Cursor);
            // The keyboard challenge is independent of the binding nonce, and
            // is never passed to the witness via a file, argument, or digest.
            string expectedText = Convert.ToHexString(RandomNumberGenerator.GetBytes(4));
            using ValidatedInputSink sink = new(control, checked((uint)desktop.Width), checked((uint)desktop.Height), evidence.Event);
            Check();
            sink.MoveTo(checked((uint)target.X), checked((uint)target.Y));
            parentProbe.Check();
            InputObservation moved = await Wait(r => r.MoveSequence > baseline.MoveSequence && r.Sequence > baseline.Sequence);
            if (moved.MovePoint != target || !moved.MoveHitOwnRoot || moved.CharacterCount != 0 ||
                moved.LeftDownCount != 0 || moved.LeftUpCount != 0 || moved.KeyDownCount != 0 || moved.KeyUpCount != 0)
                throw new ExperimentFailure("input_move_coordinate_or_baseline_mismatch");
            if (moved.PhysicalClientScreen != baseline.PhysicalClientScreen || moved.VirtualScreen != desktop)
                throw new ExperimentFailure("input_geometry_changed");
            evidence.Event("direct_input_move_observed", new { x = target.X, y = target.Y });
            Check();
            sink.LeftClick(checked((uint)target.X), checked((uint)target.Y));
            parentProbe.Check();
            InputObservation clicked = await Wait(r => r.LeftDownCount != 0 || r.LeftUpCount != 0);
            clicked = await Wait(r => r.LeftDownCount == 1 && r.LeftUpCount == 1);
            if (clicked.LeftDownPoint != target || clicked.LeftUpPoint != target ||
                clicked.LeftDownSequence <= moved.MoveSequence || clicked.LeftUpSequence <= clicked.LeftDownSequence ||
                !clicked.FocusOwn || clicked.CharacterCount != 0 || clicked.KeyDownCount != 0 || clicked.KeyUpCount != 0)
                throw new ExperimentFailure("input_button_sequence_or_point_mismatch");
            evidence.ChildReceivedExpectedButtonSequence = true;
            evidence.Event("direct_input_click_observed");
            foreach (char character in expectedText)
            {
                Check();
                sink.HexCharacter(character);
                parentProbe.Check();
                await Task.Delay(30);
            }
            InputObservation received = await Wait(r => r.CharacterCount == 8);
            if (!string.Equals(received.ReceivedHex, expectedText, StringComparison.Ordinal))
                throw new ExperimentFailure("input_received_text_mismatch");
            // Fresh reports and a quiet interval must follow delivery. A stale
            // file cannot prove that the child UI loop is still observing.
            Stopwatch quiet = Stopwatch.StartNew();
            InputObservation final = received;
            void RequireUnchanged(InputObservation observation)
            {
                if (observation.ReceivedHex != expectedText || observation.CharacterCount != 8 ||
                    observation.LeftDownCount != 1 || observation.LeftUpCount != 1 ||
                    observation.KeyDownCount != received.KeyDownCount || observation.KeyUpCount != received.KeyUpCount ||
                    observation.LeftDownPoint != target || observation.LeftUpPoint != target || !observation.FocusOwn)
                    throw new ExperimentFailure("input_changed_during_quiet_interval");
            }
            while (quiet.Elapsed < TimeSpan.FromSeconds(1))
            {
                await Task.Delay(60);
                final = Read();
                RequireUnchanged(final);
            }
            // A heartbeat near the START of the interval is insufficient. Wait
            // for a report strictly newer than the one observed at its END.
            long quietEndSequence = final.Sequence;
            final = await Wait(r => { RequireUnchanged(r); return r.Sequence > quietEndSequence; });
            RequireUnchanged(final);
            Check();
            evidence.ChildReceivedExpectedText = true;
            evidence.DirectInputChannelVerified = true;
            evidence.Event("direct_input_channel_verified", new { characters = 8, left_down = 1, left_up = 1,
                parent_probe_scope = "this_ui_thread_own_form_and_descendants", physical_device_isolation = false });
        }
        finally
        {
            parentProbe.ObserveCursor();
            evidence.ParentProbeInputEventCount = parentProbe.KeyboardCount + parentProbe.ButtonCount;
            evidence.ParentCursorUnchanged = parentProbe.CursorUnchanged;
            evidence.Event("direct_input_parent_observation", new { keyboard_messages = parentProbe.KeyboardCount,
                button_messages = parentProbe.ButtonCount, cursor_queries = parentProbe.CursorQueries,
                cursor_before = parentProbe.Before, cursor_after = parentProbe.After,
                cursor_unchanged = parentProbe.CursorUnchanged, cursor_query_error = parentProbe.FirstCursorError,
                desktop_receives_input = parentProbe.InputDesktopVerified });
            if (latest is not null)
                evidence.Event("direct_input_child_observation", new { sequence = latest.Sequence,
                    moves = latest.MoveCount, left_down = latest.LeftDownCount, left_up = latest.LeftUpCount,
                    characters = latest.CharacterCount, unexpected_characters = latest.UnexpectedCharacters,
                    repeated_characters = latest.RepeatedCharacters, overflow_characters = latest.OverflowCharacters,
                    unexpected_buttons = latest.UnexpectedButtons, system_characters = latest.SystemCharacters,
                    key_down = latest.KeyDownCount, key_up = latest.KeyUpCount,
                    failure_stage = latest.FailureStage, failure_hresult = latest.FailureHresult });
            // Record evidence before propagating an observed parent effect.
            // This cannot turn a successful child delivery into a successful
            // experiment if the parent's own input/cursor was affected.
            if (parentProbe.KeyboardCount != 0 || parentProbe.ButtonCount != 0 || !parentProbe.CursorUnchanged)
            {
                evidence.DirectInputChannelVerified = false;
                throw new ExperimentFailure("direct_input_parent_effect_observed");
            }
        }
    }

    private static void RequireHealthy(InputObservation value)
    {
        if (value.FailureStage is not null) throw new ExperimentFailure(value.FailureStage, value.FailureHresult);
        if (value.Closed || !value.Shown || !value.WindowVisible || !value.ForegroundOwn ||
            !value.DesktopInputQuerySucceeded || !value.DesktopReceivesInput)
            throw new ExperimentFailure("input_witness_ui_not_ready");
        if (value.CharacterCount is < 0 or > 8 || value.LeftDownCount is < 0 or > 1 || value.LeftUpCount is < 0 or > 1 ||
            value.UnexpectedCharacters != 0 || value.RepeatedCharacters != 0 || value.OverflowCharacters != 0 ||
            value.UnexpectedButtons != 0 || value.SystemCharacters != 0)
            throw new ExperimentFailure("input_witness_unexpected_message");
    }
}

// Thread-local, own-window observation. It intentionally does not suppress any
// input or claim to observe all parent-session processes or move-and-return
// cursor changes between samples. No hook or SendInput is used.
internal sealed class ParentInputProbe : IMessageFilter, IDisposable
{
    private readonly IntPtr window;
    private bool attached;
    internal int KeyboardCount { get; private set; }
    internal int ButtonCount { get; private set; }
    internal int CursorQueries { get; private set; }
    internal int FirstCursorError { get; private set; }
    internal bool InputDesktopVerified { get; }
    internal InputPoint? Before { get; private set; }
    internal InputPoint? After { get; private set; }
    internal bool CursorUnchanged { get; private set; } = true;

    internal ParentInputProbe(Form parent)
    {
        if (!parent.IsHandleCreated || parent.IsDisposed) throw new ExperimentFailure("parent_input_probe_window_unavailable");
        window = parent.Handle;
        bool query = InputNative.DesktopInput(InputNative.GetThreadDesktop(InputNative.GetCurrentThreadId()),
            6, out int receivesInput, sizeof(int), out uint needed);
        int error = query ? 0 : Marshal.GetLastWin32Error();
        InputDesktopVerified = query && needed == sizeof(int) && receivesInput != 0;
        if (!InputDesktopVerified) throw new ExperimentFailure("parent_input_probe_not_on_input_desktop", error);
        ObserveCursor();
        if (!CursorUnchanged) throw new ExperimentFailure("parent_input_cursor_unavailable", FirstCursorError);
        Application.AddMessageFilter(this);
        attached = true;
    }

    public bool PreFilterMessage(ref Message message)
    {
        if (message.HWnd == window || InputNative.IsChild(window, message.HWnd))
        {
            if (InputNative.KeyboardMessage(message.Msg)) KeyboardCount++;
            if (InputNative.ButtonMessage(message.Msg)) ButtonCount++;
        }
        return false;
    }

    internal void ObserveCursor()
    {
        CursorQueries++;
        if (!InputNative.GetCursorPos(out InputNative.Point point))
        {
            int error = Marshal.GetLastWin32Error();
            if (FirstCursorError == 0) FirstCursorError = error;
            CursorUnchanged = false;
            return;
        }
        Before ??= point.Value;
        After = point.Value;
        if (After != Before) CursorUnchanged = false;
    }

    internal void Check()
    {
        ObserveCursor();
        if (KeyboardCount != 0 || ButtonCount != 0 || !CursorUnchanged)
            throw new ExperimentFailure("direct_input_parent_effect_observed", FirstCursorError);
    }

    public void Dispose()
    {
        if (attached) { Application.RemoveMessageFilter(this); attached = false; }
    }
}
