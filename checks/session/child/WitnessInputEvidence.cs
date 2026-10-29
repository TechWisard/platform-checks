using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace SessionContractExperiment;

// Enabled only in the optional input witness. Observes this one Form's real
// WndProc messages. It has no source for the expected text or target point.
internal sealed class WitnessInputEvidence : IDisposable
{
    private readonly string output;
    private readonly InputObservation state;
    private readonly KeyUpDiagnosticTrace? keyUpTrace;
    private readonly Form form;
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 250 };
    private readonly Stopwatch sinceWrite = Stopwatch.StartNew();
    private bool dirty = true;
    private bool ownsOutput;
    private bool disposed;
    private int writes;

    internal WitnessInputEvidence(Form form, string identityOutput, string nonce, uint session, string digest, bool sendKeys = false)
    {
        this.form = form;
        output = Path.Combine(Path.GetDirectoryName(identityOutput)!, "witness-input.json");
        if (File.Exists(output)) throw new ExperimentFailure("input_report_already_exists");
        state = new InputObservation { Nonce = nonce, SessionId = session, IdentityDigest = digest, CharacterLimit = sendKeys ? 16 : 8 };
        if (sendKeys) keyUpTrace = KeyUpDiagnosticTrace.TryCreate();
        form.Shown += OnShown;
        timer.Tick += OnTick;
    }

    private void OnShown(object? sender, EventArgs args)
    {
        state.Shown = true;
        Write();
        timer.Start();
    }

    private void OnTick(object? sender, EventArgs args)
    {
        if (dirty || sinceWrite.Elapsed >= TimeSpan.FromSeconds(state.CharacterCount == 0 ? 5 : 1)) Write();
    }

    internal bool Observe(ref Message message)
    {
        if (!state.Shown || state.Closed || message.HWnd != form.Handle) return false;
        int id = message.Msg;
        if (id == 0x0109 && message.WParam.ToInt64() == 0xFFFF) // WM_UNICHAR capability query.
        { message.Result = new IntPtr(1); return true; }
        if (id is 0x0200 or 0x0201 or 0x0202 || InputNative.KeyboardMessage(id) || InputNative.ButtonMessage(id))
        {
            state.MessageSequence++;
            dirty = true;
        }
        if (id == 0x0200) // WM_MOUSEMOVE: signed client coordinates, not unsigned LOWORD/HIWORD.
        {
            state.MoveCount++;
            state.MoveSequence = state.MessageSequence;
            state.MovePoint = PhysicalMessagePoint(message, out bool ownRoot);
            state.MoveHitOwnRoot = ownRoot;
        }
        else if (id is 0x0201 or 0x0202)
        {
            InputPoint? point = PhysicalMessagePoint(message, out bool ownRoot);
            if (!ownRoot) state.UnexpectedButtons++;
            if (id == 0x0201)
            {
                state.LeftDownCount++;
                state.LeftDownSequence = state.MessageSequence;
                state.LeftDownPoint = point;
            }
            else
            {
                state.LeftUpCount++;
                state.LeftUpSequence = state.MessageSequence;
                state.LeftUpPoint = point;
            }
        }
        else if (InputNative.ButtonMessage(id)) state.UnexpectedButtons++;
        else if (id is 0x0100 or 0x0104) state.KeyDownCount++;
        else if (id is 0x0101 or 0x0105)
        {
            state.KeyUpCount++;
            keyUpTrace?.Observe(id, state.KeyUpCount, message.WParam.ToInt64(), message.LParam.ToInt64());
        }
        else if (id is 0x0102 or 0x0109) // WM_CHAR or actual WM_UNICHAR.
        {
            state.CharacterCount++;
            long value = message.WParam.ToInt64();
            int repeat = unchecked((ushort)message.LParam.ToInt64());
            if (repeat != 1) state.RepeatedCharacters++;
            if (value < 0 || value > 0x7F || !InputReport.IsAsciiHex((char)value))
            {
                state.UnexpectedCharacters++;
                keyUpTrace?.ObserveRejectedCharacter(value);
            }
            else if (state.ReceivedHex.Length >= state.CharacterLimit) state.OverflowCharacters++;
            else state.ReceivedHex += (char)value;
            // Consume a handled WM_UNICHAR: DefWindowProc would post WM_CHAR,
            // incorrectly counting the same real character twice. These are
            // this witness's own test messages, never another window's input.
            message.Result = IntPtr.Zero;
            return true;
        }
        else if (id is 0x0103 or 0x0106 or 0x0107) state.SystemCharacters++;
        return false;
    }

    private InputPoint? PhysicalMessagePoint(Message message, out bool ownRoot)
    {
        ownRoot = false;
        long packed = message.LParam.ToInt64();
        InputNative.Point point = new(unchecked((short)packed), unchecked((short)(packed >> 16)));
        if (!InputNative.ClientToScreen(form.Handle, ref point))
        { Fail("input_client_to_screen_failed", Marshal.GetHRForLastWin32Error()); return null; }
        ownRoot = InputNative.OwnRoot(form.Handle, InputNative.WindowFromPoint(point));
        if (!InputNative.LogicalToPhysicalPointForPerMonitorDPI(form.Handle, ref point))
        { Fail("input_physical_conversion_failed", unchecked((int)0x80004005)); return null; }
        return point.Value;
    }

    private void ObserveUi()
    {
        IntPtr window = form.Handle;
        state.WindowVisible = InputNative.IsWindowVisible(window);
        state.ForegroundOwn = InputNative.OwnRoot(window, InputNative.GetForegroundWindow());
        IntPtr focus = InputNative.GetFocus();
        state.FocusOwn = focus == window || InputNative.IsChild(window, focus);
        state.DesktopInputQuerySucceeded = InputNative.DesktopInput(
            InputNative.GetThreadDesktop(InputNative.GetCurrentThreadId()), 6, out int input, sizeof(int), out uint needed);
        state.DesktopQueryError = state.DesktopInputQuerySucceeded ? 0 : Marshal.GetLastWin32Error();
        state.DesktopReceivesInput = state.DesktopInputQuerySucceeded && needed == sizeof(int) && input != 0;
        state.MonitorCount = Screen.AllScreens.Length;
        state.VirtualScreen = InputRectangle.From(SystemInformation.VirtualScreen);
        Rectangle client = form.RectangleToScreen(form.ClientRectangle);
        state.ClientScreen = InputRectangle.From(client);
        InputNative.Point first = new(client.Left, client.Top), last = new(client.Right, client.Bottom);
        bool physical = InputNative.LogicalToPhysicalPointForPerMonitorDPI(window, ref first) &&
            InputNative.LogicalToPhysicalPointForPerMonitorDPI(window, ref last);
        state.PhysicalClientScreen = physical ? new(first.X, first.Y, last.X - first.X, last.Y - first.Y) : default;
        state.PhysicalEqualsLogical = physical && state.PhysicalClientScreen == state.ClientScreen;
        state.CursorQuerySucceeded = InputNative.GetCursorPos(out InputNative.Point cursor);
        state.CursorError = state.CursorQuerySucceeded ? 0 : Marshal.GetLastWin32Error();
        if (state.CursorQuerySucceeded)
        {
            if (!InputNative.LogicalToPhysicalPointForPerMonitorDPI(window, ref cursor))
            { state.CursorQuerySucceeded = false; state.CursorError = 0; }
            else state.Cursor = cursor.Value;
        }
    }

    private void Fail(string stage, int hresult)
    {
        state.FailureStage ??= stage;
        if (state.FailureHresult == 0) state.FailureHresult = hresult;
        dirty = true;
    }

    internal void RecordException(Exception exception)
    {
        Fail("input_witness_ui_exception", exception.HResult);
        TryFinal();
    }

    private void Write()
    {
        // Finite disk budget; reaching it is a visible failure, never a pass on
        // a frozen report. The last permitted report carries the failure.
        if (writes >= 96) return;
        if (writes == 95) { Fail("input_report_budget_exhausted", unchecked((int)0x80004005)); timer.Stop(); }
        if (form.IsHandleCreated && !form.IsDisposed) ObserveUi();
        else state.WindowVisible = false;
        state.Sequence++;
        writes++;
        state.KeyUpDiagnostics = keyUpTrace?.Snapshot();
        string temporary = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(state, InputReport.Options), new UTF8Encoding(false));
            File.Move(temporary, output, ownsOutput);
            ownsOutput = true;
            dirty = false;
            sinceWrite.Restart();
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private void TryFinal()
    {
        try { Write(); }
        catch (Exception ex) { Console.Error.WriteLine("input_witness_final_write_failed;hresult=" + ex.HResult); }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        timer.Stop();
        form.Shown -= OnShown;
        state.Closed = true;
        TryFinal();
        timer.Dispose();
    }
}
