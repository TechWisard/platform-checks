# Standard window input experiment

`-TestWindowInput` / `--test-window-input` adds an optional input check to the
existing disposable, distinct-account child-session experiment. It runs only
after the independent account identity and actual screen-captured frame
challenge pass. It cannot be combined with `-TestDirectInput`.

The experiment observes the ordinary ActiveX window input path. It deliberately
uses the parent session's input queue and moves its cursor once. A successful
result is recorded as `window_input_verified`; `direct_input_channel_verified`,
`physical_input_isolation_verified`, and `native_multiseat_verified` remain
separate and are not set by this check.

## Preconditions and input sequence

The control must be connected. The SDK `IOleInPlaceObject::GetWindow` supplies
the real control HWND, which must belong to the test process and its UI thread,
and be inside the existing AxHost and Form. The Form must already be the actual
foreground window. The test requests focus once on that exact owned control and
then verifies the resulting focus. It never calls `AttachThreadInput` or
attempts to activate a foreign foreground window.

The focused descendant may belong to another thread of the same control
process. After the single focus request, the test pins that exact HWND and its
nonzero creator thread ID. Every later check requires the same window, thread,
process and ancestry. Parent, AxHost and COM control windows still require the
original UI thread. `GetGUIThreadInfo` for both threads must agree on the pinned
focus and on an active window rooted at the parent Form. Both threads' current
keyboard layouts must match the original layout. The first bounded state
record reports these relationships without raw window, process or thread IDs.
Only the exact pinned focus HWND may also satisfy a point hit on its worker
thread; other hit windows retain the original UI-thread requirement.

Both desktops must have one monitor and unchanged, unscaled geometry. The
parent's complete native control client area must match the child's desktop
pixel dimensions, the AxHost client bounds, and the configured remote desktop
size. Smart sizing is rejected. Coordinate conversions must confirm that the
logical and physical client bounds are equal. This strict first test does not
interpret scaled viewports, scrolling, letterboxing, or mixed DPI.

Before each input submission, the test rechecks the connection and account
ownership, native window/process/thread hierarchy, foreground, focus, input
desktop, layout, geometry, and `WindowFromPoint` at the chosen parent point.
It reads both queue and asynchronous key state and rejects pre-existing pressed
keys or mouse buttons. The Win32 `INPUT` size and union offset are checked for
the actual process architecture before use.

The input consists of one absolute cursor move, one left-button down/up pair,
and eight random decimal digits, each submitted as a down/up scan-code pair.
The digits are valid characters for the existing hexadecimal witness protocol;
they avoid Shift and Caps Lock. The current parent keyboard layout must map
them without modifiers. The child must independently receive exactly the
expected digits and key transitions; a different remote layout can cause an
honest failure.

The expected text and coordinates are generated in the parent after the frame
check. They are not passed to the witness by an argument, file, nonce, or digest.
The existing child witness reports only the input its own window actually
receives. Its report is bound to the expected session, identity digest, and
nonce, with a monotonic sequence number. The parent checks the actual child
cursor move and click coordinates, one ordered button pair, eight key pairs and
eight characters. It also observes the corresponding messages in the real
parent control window. A quiet interval and a strictly newer child heartbeat
must follow the sequence.

The existing UI-thread message filter and an optional observer of the pinned
worker thread report separate actual counts. The worker observer uses a
thread-specific `WH_GETMESSAGE` hook in the same process, counts only messages
removed from that queue, and reads only the message's window and type. It never
reads key values, changes a message or stops the hook chain. An opened thread
handle pins the original worker identity and must remain live for input and
receipt-bound release checks. Immediately before the first test event, the
parent captures an immutable baseline of both queues without resetting either
observer. Two idle worker snapshots must have identical complete input counters;
the UI snapshot is taken synchronously on its own thread between them. The
snapshot attempt lasts at most one second within the existing input budget.
Each total must equal the sum of its captured categories. Text, system-key,
other-button, outside-target, overflow and error observations reject a baseline.
Down/up counts must balance; the emitter separately rechecks actual queue and
asynchronous pressed state before any submission. Balanced pre-emission pairs
are reported with their unknown origin, never labelled as test input.

Success requires increments of exactly eight key-down and eight key-up messages
and one left-button down/up pair from that immutable baseline across the two
distinct threads. Every counter must be monotonic; any new outside-target,
system-key, other-button, overflow or observer failure rejects the result. The
same delta checks run again after observer shutdown. With no worker thread,
only the actual UI counts participate. Raw absolute observations and the
baseline are preserved in the report.

## Failure and cleanup

The input budget is at most 25 seconds of the already remaining session-test
budget. Fewer than 12 remaining seconds reject the test before injection.

Before input, an observation-only phase requires two fresh empty child reports
within at most 12 seconds of the same total budget. The witness publishes its
initial state in `Shown` and then uses a five-second idle heartbeat. Reports
must bind the expected nonce, session and identity and have monotonic sequence
numbers, no failure or keyboard/button input, and the original visibility,
focus and input-desktop conditions. Only the child's own foreground flag may
be absent before the planned pointer and click. The parent's exact foreground,
focus, ownership and worker-observer guards remain strict throughout.

The existing single cursor move must produce a fresh child `WM_MOUSEMOVE` at
the exact mapped point with `MoveHitOwnRoot=true`, unchanged geometry and zero
keyboard/button counts. Only this independent receipt authorizes the existing
single click at that same point. It serves as ordinary activation of the proven
visible witness; no extra click, key, focus request, foreign-window action or
queue attachment is added. A stale pre-click report may remain visible while
the click is pending. Every hard failure, other missing UI condition, unexpected
input, keyboard/text count or invalid button count still rejects immediately.

Before any keyboard pair, a fresh report must contain exactly one ordered
button down/up pair at that point and the full original own-foreground and focus
health. If the click does not establish this, the test times out without sending
keyboard input. All subsequent reads use the original strict health predicate,
including immediate rejection of foreground loss. Exact child text, key counts,
point/order checks, quiet interval and fresh final heartbeat are unchanged.

Each `SendInput` return count is recorded. Only a returned count of one creates
an owned pending-down receipt for a two-event pair; zero creates no receipt,
and two means both events were accepted. An exceptional interop call has no
insertion receipt and is reported as unknown, with cleanup unverified instead
of emitting an assumed release. Cleanup submits at most one matching keyboard UP and
one matching mouse UP, only while the owned target and cursor still satisfy the
same guards. It never retries a DOWN or releases an arbitrary pre-existing key.
Accepted UP submission alone is insufficient: cleanup allows the UI loop to
run, then checks the queue and asynchronous state for the owned keys/button,
with at most 20 observations at 25 ms intervals. The overall input result
cannot pass if this cleanup is unverified. `window_input_cleanup_verified` is
null when this input test was not requested.

Observation failure stops new emissions and functional acceptance, while the
ownership checks remain available for a release backed by an existing partial
DOWN receipt. The worker hook is removed after those releases, including when
release cleanup itself fails. Cleanup requires successful hook removal, bounded
retirement and release of the pinned thread handle. An exceptional installation
call without an observed native return leaves cleanup unverified. A static
delegate and inert state remain rooted until this disposable process exits
because a callback may already be entering when unhook returns. Observing idle
callbacks does not establish that no later inert callback can enter.

Combined actual message deltas are checked again after observer shutdown.
`window_input_cleanup_verified` includes both input-release and observer
cleanup results; neither result alone permits success.

This is a bounded disposable-VM test, not an input isolation mechanism.
Foreground and hit-test checks precede submission but cannot make the global
input queue atomic with respect to another actor changing focus. Any observed
target change aborts the test; it does not authorize further input to another
application. It does not restore the cursor to a potentially foreign window
afterward. Native COM/Win32 calls are not cancellable by this managed time
budget, so the existing external process timeout remains required.

## Interpretation

A pass establishes delivery through the standard parent ActiveX window path to
the separately verified child witness in this environment. A native OLE host
uses the same standard window focus and keyboard message path, but this managed
component test does not execute or validate another host's complete OLE site,
message pump, lifetime management, or executable. Physical device assignment,
exclusive input filtering, multiple physical seats, and GPU routing are outside
this result.

Local cross-compilation is a build check only. An actual Windows run must also
pass the preceding frame challenge; a compiled experiment whose frame gate
fails has not verified input.

The runner also validates the final report's exact schema and status, typed
Boolean frame/account/input/cleanup fields, and separate false direct-input and
physical-isolation fields. When child preparation was requested, its typed
render-eligibility and cleanup fields must pass too; preparation success and
the narrowly permitted unresolved-foreground observation remain distinct.
A successful process exit with
missing or inconsistent evidence is rejected; reported flags cannot override a
nonzero process exit.

## SDK contracts

- [IOleWindow::GetWindow](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-iolewindow-getwindow)
- [IOleInPlaceObject](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nn-oleidl-ioleinplaceobject)
- [SetFocus](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setfocus)
- [GetGUIThreadInfo](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getguithreadinfo)
- [GetKeyboardLayout](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getkeyboardlayout)
- [GetMsgProc](https://learn.microsoft.com/en-us/windows/win32/winmsg/getmsgproc)
- [SetWindowsHookExW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw)
- [UnhookWindowsHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex)
- [SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)
- [MOUSEINPUT](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput)
- [KEYBDINPUT](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput)
- [IOleInPlaceActiveObject::TranslateAccelerator](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-ioleinplaceactiveobject-translateaccelerator)
