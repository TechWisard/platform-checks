using System.Globalization;
using System.Runtime.InteropServices;

namespace SessionContractExperiment;

internal static class NativeHostTranslationPolicy
{
    internal static bool CountsMatch(int uiKeyDownDelta, int uiKeyUpDelta, uint nativeKeyDown, uint nativeKeyUp) =>
        uiKeyDownDelta is >= 0 and <= 8 && uiKeyUpDelta is >= 0 and <= 8 &&
        nativeKeyDown == (uint)uiKeyDownDelta && nativeKeyUp == (uint)uiKeyUpDelta;

    internal static bool KeyPathObserved(int uiKeyDownDelta, int uiKeyUpDelta, uint nativeKeyDown, uint nativeKeyUp) =>
        CountsMatch(uiKeyDownDelta, uiKeyUpDelta, nativeKeyDown, nativeKeyUp) &&
        (uiKeyDownDelta != 0 || uiKeyUpDelta != 0);
}

// Opt-in test adapter around the unchanged native OLE host and event sink.
// Account/session/witness/input policy remains in the independent C# fixture.
internal sealed class NativeOleHost : Control
{
    [ThreadStatic] private static int protocolDepth;
    [ThreadStatic] private static NativeOleHost? active;
    // While a failed shutdown leaves the native handle unconsumed, retain the
    // context and any remaining unique RCW until this disposable process exits.
    // A consumed handle can still report failed cleanup; that is never success.
    private static readonly List<object> retainedUntilProcessExit = new();
    private readonly uint owner = InputNative.GetCurrentThreadId();
    private readonly Action<string, object?> record;
    private IntPtr context;
    private object? control;
    private uint eventsRead;
    private bool created, closing, closed, resizeDeferred;
    private int nativeDepth;
    private int translationSuppressed;
    private string? callbackFailureStage;
    private int callbackFailureCode;

    internal NativeOleHost(Action<string, object?> record)
    {
        this.record = record;
        SetStyle(ControlStyles.UserPaint, false);
        TabStop = true;
    }

    protected override CreateParams CreateParams
    {
        get { CreateParams value = base.CreateParams; value.Style |= 0x02000000 /* WS_CLIPCHILDREN */; return value; }
    }

    internal object ControlObject
    {
        get
        {
            RequireOwner();
            if (control is not null) return control;
            if (created || closing || closed || active is not null)
                throw new ExperimentFailure("native_host_single_owner_required");
            _ = Handle;
            IntPtr transferred = IntPtr.Zero;
            try
            {
                created = true;
                Call(() => Api.native_host_create(Handle, ClientSize.Width, ClientSize.Height, out context, out transferred),
                    "native_host_create_failed");
                if (context == IntPtr.Zero || transferred == IntPtr.Zero)
                    throw new ExperimentFailure("native_host_create_outputs_missing");
                // Create one private RCW. It is never shared with other hosts;
                // the single transfer AddRef from C++ is released below.
                control = Marshal.GetUniqueObjectForIUnknown(transferred);
                active = this;
                record("native_host_created", ReadSnapshot().Evidence());
                return control;
            }
            catch { Abandon(); throw; }
            finally { if (transferred != IntPtr.Zero) Marshal.Release(transferred); }
        }
    }

    internal readonly struct ProtocolCall : IDisposable
    {
        public void Dispose()
        {
            if (--protocolDepth == 0) active?.ApplyDeferredResize();
        }
    }
    internal static ProtocolCall EnterProtocolCall() { ++protocolDepth; return new(); }

    private void RequireOwner()
    {
        if (InputNative.GetCurrentThreadId() != owner)
            throw new ExperimentFailure("native_host_wrong_owner_thread");
    }
    private int Call(Func<int> action, string stage, bool allowFalse = false)
    {
        RequireOwner();
        ++nativeDepth;
        try
        {
            int result = action();
            if (result != 0 && !(allowFalse && result == 1)) throw new ExperimentFailure(stage, result);
            return result;
        }
        finally { --nativeDepth; }
    }
    protected override void OnResize(EventArgs args)
    {
        try
        {
            base.OnResize(args);
            if (context == IntPtr.Zero || closing || closed) return;
            resizeDeferred = true;
            ApplyDeferredResize();
        }
        catch (Exception error) { LatchCallbackFailure("native_host_resize_callback_failed", error); }
    }
    private void ApplyDeferredResize()
    {
        if (!resizeDeferred || context == IntPtr.Zero || closing || closed || protocolDepth != 0 || nativeDepth != 0) return;
        if (ClientSize.Width <= 0 || ClientSize.Height <= 0) return;
        resizeDeferred = false;
        Call(() => Api.native_host_resize(context, ClientSize.Width, ClientSize.Height), "native_host_resize_failed");
    }
    internal void FocusHostedControl()
    {
        RequireOwner();
        if (context == IntPtr.Zero || closing || protocolDepth != 0 || nativeDepth != 0)
            throw new ExperimentFailure("native_host_focus_not_ready");
        ApplyDeferredResize();
        Call(() => Api.native_host_focus(context), "native_host_focus_failed");
    }

    // Called by WindowMessageObservation only AFTER that observer has counted
    // the same queued message. No independent earlier filter can hide an event
    // consumed by the native TranslateAccelerator call from the parent proof.
    internal bool TranslateAfterObservation(ref Message message)
    {
        try
        {
            if (message.Msg < 0x0100 || message.Msg > 0x0109) return false;
            RequireOwner();
            if (context == IntPtr.Zero || closing) throw new ExperimentFailure("native_host_translation_not_ready");
            if (nativeDepth != 0 || protocolDepth != 0)
            {
                ++translationSuppressed;
                throw new ExperimentFailure("native_host_translation_reentered");
            }
            IntPtr window = message.HWnd, wparam = message.WParam, lparam = message.LParam;
            uint id = checked((uint)message.Msg);
            return Call(() => Api.native_host_translate(context, window, id, wparam, lparam),
                "native_host_translation_failed", allowFalse: true) == 0;
        }
        catch (Exception error)
        {
            // Never unwind Application.Run while its asynchronous owner is
            // suspended. Its next Check raises this inside the awaited try so
            // the existing receipt-based input/session finally blocks execute.
            LatchCallbackFailure("native_host_translation_callback_failed", error);
            return false;
        }
    }
    private void LatchCallbackFailure(string stage, Exception error)
    {
        if (callbackFailureStage is not null) return;
        callbackFailureCode = error is ExperimentFailure known ? known.Code : error.HResult;
        callbackFailureStage = stage;
    }
    internal void ThrowIfCallbackFailed()
    {
        RequireOwner();
        if (callbackFailureStage is not null) throw new ExperimentFailure(callbackFailureStage, callbackFailureCode);
    }

    internal void VerifySuccessfulWindowPath(int uiKeyDownDelta, int uiKeyUpDelta)
    {
        ThrowIfCallbackFailed();
        if (uiKeyDownDelta is < 0 or > 8 || uiKeyUpDelta is < 0 or > 8)
            throw new ExperimentFailure("native_host_ui_observation_count_invalid");
        Snapshot value = ReadSnapshot();
        DrainEvents(value);
        bool translationCountsMatch = NativeHostTranslationPolicy.CountsMatch(
            uiKeyDownDelta, uiKeyUpDelta, value.KeyDownTranslated, value.KeyUpTranslated);
        record("native_host_connected_frame_input", new { snapshot = value.Evidence(), translation_suppressed = translationSuppressed,
            expected_container_key_down = uiKeyDownDelta, expected_container_key_up = uiKeyUpDelta,
            ui_key_counts_are_immutable_baseline_deltas = true,
            container_key_translation_exercised = NativeHostTranslationPolicy.KeyPathObserved(
                uiKeyDownDelta, uiKeyUpDelta, value.KeyDownTranslated, value.KeyUpTranslated),
            translation_expectation_basis = "actual_ui_thread_filter_deltas_after_full_child_combined_thread_and_cleanup_acceptance",
            execution_scope = "exact_generic_native_host_and_event_sink_in_independent_managed_fixture",
            full_native_viewer_executed = false, full_native_binding_executed = false });
        if (value.ParentOwned != 1 || value.StaVerified != 1 || value.ClientSiteAttached != 1 ||
            value.InPlaceActive != 1 || value.UiActive != 1 || value.ControlWindowIsChild != 1 ||
            value.ActivationCount == 0 || value.FocusCalls != 1 ||
            !translationCountsMatch ||
            value.TranslationFailed != 0 || translationSuppressed != 0 || value.EventOverflow != 0 || value.EventContractFailed != 0 ||
            value.ConnectingSequence == 0 || value.ConnectedSequence <= value.ConnectingSequence ||
            value.LoginSequence <= value.ConnectedSequence || value.DisconnectedSequence != 0)
            throw new ExperimentFailure("native_host_connected_path_gate_failed");
    }

    internal void BeginCleanup()
    {
        RequireOwner(); closing = true;
        if (context != IntPtr.Zero) Call(() => Api.native_host_begin_cleanup(context), "native_host_cleanup_start_failed");
    }
    internal bool CloseDisconnected(bool fixtureDisconnected)
    {
        RequireOwner();
        if (nativeDepth != 0 || protocolDepth != 0)
            throw new ExperimentFailure("native_host_reentrant_close_rejected");
        if (!created) return false;
        if (context == IntPtr.Zero) throw new ExperimentFailure("native_host_context_lost_before_close");
        if (!fixtureDisconnected) throw new ExperimentFailure("native_host_fixture_disconnect_unverified");
        BeginCleanup();
        Snapshot before = ReadSnapshot(); DrainEvents(before);
        Snapshot final = EmptySnapshot();
        int consumed = 0;
        int result;
        ++nativeDepth;
        try
        {
            // The caller has disposed its password, event, and extended-interface
            // owners and stopped using every alias before releasing this unique RCW.
            if (control is not null)
            {
                int remaining = Marshal.FinalReleaseComObject(control);
                control = null;
                if (remaining != 0) throw new ExperimentFailure("native_host_unique_rcw_release_incomplete", remaining);
            }
            result = Api.native_host_close(context, ref final, out consumed);
        }
        finally
        {
            --nativeDepth;
            if (consumed != 0) { context = IntPtr.Zero; closed = true; if (active == this) active = null; }
        }
        record("native_host_close_result", new { snapshot = final.Evidence(), close_hresult = result, handle_consumed = consumed == 1,
            unique_rcw_released = control is null, full_native_viewer_executed = false });
        if (result != 0 || consumed != 1 || final.SinkDetached != 1 || final.Unadvised != 1 || final.HostClosed != 1 ||
            final.ControlWindowDestroyed != 1 || final.ReferencesReleased != 1 || final.OleBalanced != 1 ||
            final.UnadviseHresult != 0 || final.HostCloseHresult != 0)
            throw new ExperimentFailure("native_host_close_not_verified", result);
        return true;
    }

    private Snapshot ReadSnapshot()
    {
        Snapshot value = EmptySnapshot();
        Call(() => Api.native_host_snapshot(context, ref value), "native_host_snapshot_failed");
        if (value.Size != Marshal.SizeOf<Snapshot>() || value.Version != 1)
            throw new ExperimentFailure("native_host_snapshot_abi_mismatch");
        return value;
    }
    private void DrainEvents(Snapshot value)
    {
        if (value.EventCount > 256 || eventsRead > value.EventCount)
            throw new ExperimentFailure("native_host_event_count_invalid");
        while (eventsRead < value.EventCount)
        {
            Event item = default;
            Call(() => Api.native_host_event(context, eventsRead, out item), "native_host_event_read_failed");
            if (item.Sequence != ++eventsRead || item.Kind > 10)
                throw new ExperimentFailure("native_host_event_record_invalid");
            record("native_host_event", new { item.Sequence, item.Kind, item.Code });
        }
    }
    private void Abandon()
    {
        if (context != IntPtr.Zero)
        {
            int result = Api.native_host_abandon(context);
            record("native_host_abandoned", new { hresult = result, cleanup_verified = false });
            // Native owns its inert callback target and COM references for the
            // remaining process lifetime. Do not free this context from a GC finalizer.
            context = IntPtr.Zero;
        }
        if (control is not null) { retainedUntilProcessExit.Add(control); control = null; }
        if (active == this) active = null;
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing && context != IntPtr.Zero) { RequireOwner(); Abandon(); }
        base.Dispose(disposing);
    }
    private static Snapshot EmptySnapshot() => new() { Size = checked((uint)Marshal.SizeOf<Snapshot>()), Version = 1 };

    [StructLayout(LayoutKind.Sequential)]
    internal struct Snapshot
    {
        public uint Size, Version, ParentOwned, StaVerified, ClientSiteAttached;
        public uint InPlaceActive, UiActive, ControlWindowIsChild, ActivationCount, FocusCalls, ResizeCalls;
        public uint KeyDownTranslated, KeyUpTranslated, OtherKeyTranslated;
        public uint TranslationHandled, TranslationDeclined, TranslationFailed;
        public uint EventCount, EventOverflow, EventContractFailed;
        public uint ConnectingSequence, ConnectedSequence, LoginSequence, DisconnectedSequence;
        public uint CleanupStarted, SinkDetached, Unadvised, HostClosed;
        public uint ControlWindowDestroyed, ReferencesReleased, OleBalanced;
        public int UnadviseHresult, HostCloseHresult;
        internal readonly object Evidence() => new {
            Size, Version, ParentOwned, StaVerified, ClientSiteAttached,
            InPlaceActive, UiActive, ControlWindowIsChild, ActivationCount, FocusCalls, ResizeCalls,
            KeyDownTranslated, KeyUpTranslated, OtherKeyTranslated,
            TranslationHandled, TranslationDeclined, TranslationFailed,
            EventCount, EventOverflow, EventContractFailed,
            ConnectingSequence, ConnectedSequence, LoginSequence, DisconnectedSequence,
            CleanupStarted, SinkDetached, Unadvised, HostClosed,
            ControlWindowDestroyed, ReferencesReleased, OleBalanced, UnadviseHresult, HostCloseHresult
        };
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Event { public uint Sequence, Kind; public int Code; }

    private static class Api
    {
        private const string Library = "NativeHostBridge.dll";
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_create(IntPtr parent, int width, int height, out IntPtr context, out IntPtr control);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_snapshot(IntPtr context, ref Snapshot snapshot);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_event(IntPtr context, uint index, out Event item);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_resize(IntPtr context, int width, int height);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_focus(IntPtr context);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_translate(IntPtr context, IntPtr window, uint message, IntPtr wparam, IntPtr lparam);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_begin_cleanup(IntPtr context);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_close(IntPtr context, ref Snapshot snapshot, out int consumed);
        [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int native_host_abandon(IntPtr context);
    }
}
