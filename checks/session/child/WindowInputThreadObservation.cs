using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SessionContractExperiment;

// Independent test instrumentation for one pinned, same-process worker thread.
// It observes removed queued messages; it never reads key values or message text,
// changes a message, sends input, attaches queues, or calls into the COM control.
// https://learn.microsoft.com/windows/win32/winmsg/getmsgproc
// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setwindowshookexw
internal sealed class WindowInputThreadObservation
{
    private const int Closed = int.MinValue;
    private const int MaximumInputMessages = 128;
    private const uint ThreadQueryLimitedInformation = 0x0800;
    private const uint Synchronize = 0x00100000;
    private const uint WaitTimeout = 0x00000102;

    // One observer per disposable experiment process. Neither root is cleared:
    // UnhookWindowsHookEx may return while a callback is about to enter. A late
    // callback only chains onward after retirement; its code/state remain valid.
    private static readonly HookProcedure CallbackRoot = HookCallback;
    private static WindowInputThreadObservation? lifetimeRoot;

    private readonly IntPtr parentWindow;
    private readonly IntPtr controlWindow;
    private readonly IntPtr focusWindow;
    private readonly uint uiThread;
    private readonly uint focusThread;
    private readonly uint ownerProcess;
    private IntPtr threadHandle;
    private IntPtr hook;
    private Task<bool>? stopTask;
    private int observationGate = Closed;
    private int activeCallbacks;
    private long failure;
    private int installationAttempted, installationReturned, installed, threadPinned;
    private int unhookAttempted, unhookSucceeded, threadHandleReleased, cleanupVerified;
    private int callbacksObservedIdle;
    private int installError, unhookError;
    private int total, keyDown, keyUp, characters, leftDown, leftUp, otherButtons, systemKeys;
    private int outsideTargetInput, overflow;

    private enum FailureKind
    {
        None, DuplicateObserver, InvalidBinding, ThreadOpen, ThreadIdentity,
        HookInstall, InitializationException, ObservationStopped, CallbackThread,
        NullMessage, MessageOwner, CallbackException, HookChainException,
        HookRemoval, RetirementTimeout, ThreadHandleClose, StopWrongThread, StopException,
        HookInstallOutcomeUnknown
    }

    internal readonly record struct Observation(
        int KeyDown, int KeyUp, int Characters, int LeftDown, int LeftUp,
        int OtherButtons, int SystemKeys, int OutsideTargetInput, int Total,
        bool Overflow, bool Failure, int FailureStage, int FailureCode,
        bool InstallationAttempted, bool InstallationReturned, bool Installed, bool Retired,
        bool UnhookAttempted, bool UnhookSucceeded, bool ThreadPinned,
        bool ThreadHandleReleased, bool CleanupVerified,
        int InstallError, int UnhookError, int ActiveCallbacks, int ActiveRecorders,
        bool CallbacksObservedIdle);

    // The caller must keep the returned instance even if installation failed,
    // call RequireHealthy before input, and always await StopAsync in finally.
    // Failures after acquiring a native resource are latched rather than thrown
    // from this constructor, so the owner can perform the same awaited cleanup.
    internal WindowInputThreadObservation(IntPtr parentWindow, IntPtr controlWindow,
        IntPtr focusWindow, uint uiThread, uint focusThread, uint ownerProcess)
    {
        this.parentWindow = parentWindow;
        this.controlWindow = controlWindow;
        this.focusWindow = focusWindow;
        this.uiThread = uiThread;
        this.focusThread = focusThread;
        this.ownerProcess = ownerProcess;

        if (Interlocked.CompareExchange(ref lifetimeRoot, this, null) is not null)
        {
            Latch(FailureKind.DuplicateObserver);
            return;
        }
        try
        {
            if (uiThread == 0 || focusThread == 0 || uiThread == focusThread ||
                ownerProcess == 0 || Native.GetCurrentProcessId() != ownerProcess ||
                Native.GetCurrentThreadId() != uiThread || !WindowTupleMatches())
            {
                Latch(FailureKind.InvalidBinding);
                return;
            }
            threadHandle = Native.OpenThread(ThreadQueryLimitedInformation | Synchronize,
                false, focusThread);
            if (threadHandle == IntPtr.Zero)
            {
                Latch(FailureKind.ThreadOpen, Marshal.GetLastPInvokeError());
                return;
            }
            if (!PinnedThreadAlive())
            {
                Latch(FailureKind.ThreadIdentity);
                return;
            }
            Volatile.Write(ref threadPinned, 1);
            if (!WindowTupleMatches())
            {
                Latch(FailureKind.InvalidBinding);
                return;
            }
            Interlocked.Exchange(ref observationGate, 0);
            Volatile.Write(ref installationAttempted, 1);
            hook = Native.SetWindowsHookExW(3 /* WH_GETMESSAGE */, CallbackRoot,
                IntPtr.Zero, focusThread);
            Volatile.Write(ref installationReturned, 1);
            if (hook == IntPtr.Zero)
            {
                installError = Marshal.GetLastPInvokeError();
                Latch(FailureKind.HookInstall, installError);
                return;
            }
            Volatile.Write(ref installed, 1);
            if (!PinnedThreadAlive() || !WindowTupleMatches())
                Latch(FailureKind.ThreadIdentity);
        }
        catch (Exception exception)
        {
            Latch(FailureKind.InitializationException, exception.HResult);
        }
        finally
        {
            if (Volatile.Read(ref installed) == 0) Retire();
        }
    }

    internal Observation Snapshot
    {
        get
        {
            long observedFailure = Volatile.Read(ref failure);
            int gate = Volatile.Read(ref observationGate);
            return new(Volatile.Read(ref keyDown), Volatile.Read(ref keyUp),
                Volatile.Read(ref characters), Volatile.Read(ref leftDown), Volatile.Read(ref leftUp),
                Volatile.Read(ref otherButtons), Volatile.Read(ref systemKeys),
                Volatile.Read(ref outsideTargetInput), Volatile.Read(ref total),
                Volatile.Read(ref overflow) != 0, observedFailure != 0,
                (int)(observedFailure >> 32), unchecked((int)observedFailure),
                Volatile.Read(ref installationAttempted) != 0,
                Volatile.Read(ref installationReturned) != 0, Volatile.Read(ref installed) != 0,
                gate < 0, Volatile.Read(ref unhookAttempted) != 0,
                Volatile.Read(ref unhookSucceeded) != 0, Volatile.Read(ref threadPinned) != 0,
                Volatile.Read(ref threadHandleReleased) != 0, Volatile.Read(ref cleanupVerified) != 0,
                Volatile.Read(ref installError), Volatile.Read(ref unhookError),
                Volatile.Read(ref activeCallbacks), gate & int.MaxValue,
                Volatile.Read(ref callbacksObservedIdle) != 0);
        }
    }

    // Use only in the awaited/new-emission checks. A latched observer error must
    // not prevent the existing ownership-checked release of an accepted DOWN.
    internal void RequireHealthy()
    {
        RequireBinding();
        if (Volatile.Read(ref installed) == 0 || Volatile.Read(ref observationGate) < 0)
            Latch(FailureKind.ObservationStopped);

        Observation observed = Snapshot;
        if (observed.Failure || observed.Overflow || observed.OutsideTargetInput != 0)
            throw new ExperimentFailure("window_input_worker_observation_failed", observed.FailureCode);
    }

    // Identity remains mandatory for a pending-UP release even after observer
    // failure. This deliberately does not test the observation failure latch.
    internal void RequireBinding()
    {
        if (Native.GetCurrentThreadId() != uiThread || Native.GetCurrentProcessId() != ownerProcess ||
            !PinnedThreadAlive() || !WindowTupleMatches())
        {
            Latch(FailureKind.ThreadIdentity);
            throw new ExperimentFailure("window_input_worker_binding_changed");
        }
    }

    internal Task<bool> StopAsync() => stopTask ??= StopCoreAsync();

    private async Task<bool> StopCoreAsync()
    {
        Retire();
        try
        {
            if (Native.GetCurrentThreadId() != uiThread || Native.GetCurrentProcessId() != ownerProcess)
            {
                Latch(FailureKind.StopWrongThread);
                return false;
            }
            if (hook != IntPtr.Zero)
            {
                Volatile.Write(ref unhookAttempted, 1);
                if (!Native.UnhookWindowsHookEx(hook))
                {
                    unhookError = Marshal.GetLastPInvokeError();
                    Latch(FailureKind.HookRemoval, unhookError);
                    return false; // Keep both native handles and managed roots.
                }
                Volatile.Write(ref unhookSucceeded, 1);
                hook = IntPtr.Zero;
            }
            if (Volatile.Read(ref installationAttempted) != 0 &&
                Volatile.Read(ref installationReturned) == 0)
            {
                // A native call that threw without returning a usable result
                // does not prove that no hook was installed. Retain the inert
                // rooted state and report cleanup unknown, never success.
                Latch(FailureKind.HookInstallOutcomeUnknown);
                return false;
            }

            // The closed admission gate makes the recorder count stable at
            // zero. Also observe that currently executing callbacks reached
            // zero, without claiming that no late callback can enter later.
            // Late callbacks retain valid state and never touch windows or the
            // thread handle; they only call next.
            Stopwatch deadline = Stopwatch.StartNew();
            while (((Volatile.Read(ref observationGate) & int.MaxValue) != 0 ||
                Volatile.Read(ref activeCallbacks) != 0) &&
                deadline.Elapsed < TimeSpan.FromSeconds(1))
                await Task.Delay(10);
            if ((Volatile.Read(ref observationGate) & int.MaxValue) != 0 ||
                Volatile.Read(ref activeCallbacks) != 0)
            {
                Latch(FailureKind.RetirementTimeout);
                return false;
            }
            Volatile.Write(ref callbacksObservedIdle, 1);
            if (threadHandle != IntPtr.Zero)
            {
                if (!Native.CloseHandle(threadHandle))
                {
                    Latch(FailureKind.ThreadHandleClose, Marshal.GetLastPInvokeError());
                    return false;
                }
                threadHandle = IntPtr.Zero;
            }
            Volatile.Write(ref threadHandleReleased, 1);
            Volatile.Write(ref cleanupVerified, 1);
            return true;
        }
        catch (Exception exception)
        {
            Latch(FailureKind.StopException, exception.HResult);
            return false;
        }
    }

    private bool PinnedThreadAlive() => threadHandle != IntPtr.Zero &&
        Native.GetThreadId(threadHandle) == focusThread &&
        Native.GetProcessIdOfThread(threadHandle) == ownerProcess &&
        Native.WaitForSingleObject(threadHandle, 0) == WaitTimeout;

    private bool WindowTupleMatches()
    {
        if (parentWindow == IntPtr.Zero || controlWindow == IntPtr.Zero ||
            focusWindow == IntPtr.Zero || controlWindow == parentWindow || focusWindow == controlWindow ||
            !OwnerMatches(parentWindow, uiThread) || !OwnerMatches(controlWindow, uiThread) ||
            !OwnerMatches(focusWindow, focusThread) ||
            !InputNative.IsChild(parentWindow, controlWindow) ||
            !InputNative.IsChild(controlWindow, focusWindow) ||
            InputNative.GetForegroundWindow() != parentWindow || InputNative.GetFocus() != focusWindow)
            return false;
        return true;
    }

    private bool OwnerMatches(IntPtr window, uint expectedThread)
    {
        uint actualThread = Native.GetWindowThreadProcessId(window, out uint actualProcess);
        return actualThread != 0 && actualThread == expectedThread && actualProcess == ownerProcess;
    }

    private void Retire() => Interlocked.Or(ref observationGate, Closed);

    private bool TryEnterRecorder()
    {
        while (true)
        {
            int state = Volatile.Read(ref observationGate);
            if (state < 0) return false;
            if (Interlocked.CompareExchange(ref observationGate, state + 1, state) == state) return true;
        }
    }

    private void ExitRecorder() => Interlocked.Decrement(ref observationGate);

    private void Latch(FailureKind kind, int code = 0) =>
        Interlocked.CompareExchange(ref failure, ((long)kind << 32) | unchecked((uint)code), 0);

    private static IntPtr HookCallback(int code, UIntPtr removal, IntPtr message)
    {
        WindowInputThreadObservation? current = Volatile.Read(ref lifetimeRoot);
        if (current is not null) Interlocked.Increment(ref current.activeCallbacks);
        try
        {
            try
            {
                // HC_ACTION == 0. Never inspect a negative-code notification,
                // PM_NOREMOVE peek, unknown code, or retired observation.
                if (current is not null && code == 0 && removal == new UIntPtr(1) && current.TryEnterRecorder())
                {
                    try { current.ObserveRemovedMessage(message); }
                    finally { current.ExitRecorder(); }
                }
            }
            catch (Exception exception)
            {
                current?.Latch(FailureKind.CallbackException, exception.HResult);
            }

            // Always attempt the next hook with the exact untouched arguments;
            // the HHOOK argument is documented as ignored. No managed UI/COM
            // callback, await, logging, or message mutation occurs here.
            try { return Native.CallNextHookEx(IntPtr.Zero, code, removal, message); }
            catch (Exception exception)
            {
                current?.Latch(FailureKind.HookChainException, exception.HResult);
                return IntPtr.Zero;
            }
        }
        finally
        {
            if (current is not null) Interlocked.Decrement(ref current.activeCallbacks);
        }
    }

    private void ObserveRemovedMessage(IntPtr message)
    {
        if (Volatile.Read(ref failure) != 0 || Volatile.Read(ref overflow) != 0) return;
        if (Native.GetCurrentThreadId() != focusThread || Native.GetCurrentProcessId() != ownerProcess)
        {
            Latch(FailureKind.CallbackThread);
            return;
        }
        if (message == IntPtr.Zero)
        {
            Latch(FailureKind.NullMessage);
            return;
        }
        // Only the SDK MSG prefix is read: HWND at offset 0, UINT message at
        // sizeof(HWND). No wParam/lParam payload, scan code, text, or coordinates.
        int kind = Marshal.ReadInt32(message, IntPtr.Size);
        if (!InputNative.KeyboardMessage(kind) && !InputNative.ButtonMessage(kind)) return;
        if (Interlocked.Increment(ref total) > MaximumInputMessages)
        {
            Volatile.Write(ref overflow, 1);
            return;
        }
        IntPtr window = Marshal.ReadIntPtr(message);
        if (!PinnedThreadAlive() || !WindowTupleMatches() || !OwnerMatches(window, focusThread))
        {
            Interlocked.Increment(ref outsideTargetInput);
            Latch(FailureKind.MessageOwner);
            return;
        }
        if (window != controlWindow && !InputNative.IsChild(controlWindow, window))
        {
            Interlocked.Increment(ref outsideTargetInput);
            return;
        }
        switch (kind)
        {
            case 0x0100: Interlocked.Increment(ref keyDown); break;
            case 0x0101: Interlocked.Increment(ref keyUp); break;
            case 0x0102: case 0x0109: Interlocked.Increment(ref characters); break;
            case 0x0104: case 0x0105: case 0x0106: case 0x0107: Interlocked.Increment(ref systemKeys); break;
            case 0x0201: Interlocked.Increment(ref leftDown); break;
            case 0x0202: Interlocked.Increment(ref leftUp); break;
            default:
                if (InputNative.ButtonMessage(kind)) Interlocked.Increment(ref otherButtons);
                break;
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr HookProcedure(int code, UIntPtr removal, IntPtr message);

    private static class Native
    {
        [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr SetWindowsHookExW(int hook, HookProcedure callback, IntPtr module, uint thread);
        [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool UnhookWindowsHookEx(IntPtr hook);
        [DllImport("user32.dll", ExactSpelling = true)]
        internal static extern IntPtr CallNextHookEx(IntPtr hook, int code, UIntPtr removal, IntPtr message);
        [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern uint GetCurrentThreadId();
        [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern uint GetCurrentProcessId();
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern IntPtr OpenThread(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint thread);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern uint GetThreadId(IntPtr thread);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern uint GetProcessIdOfThread(IntPtr thread);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }
}
