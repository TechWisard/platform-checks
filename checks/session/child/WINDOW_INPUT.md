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
then verifies the resulting focus. It never attaches another thread's input
queue or attempts to activate a foreign foreground window.

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

## Failure and cleanup

The input budget is at most 25 seconds of the already remaining session-test
budget. Fewer than 12 remaining seconds reject the test before injection.

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
verification and cleanup fields must pass too. A successful process exit with
missing or inconsistent evidence is rejected; reported flags cannot override a
nonzero process exit.

## SDK contracts

- [IOleWindow::GetWindow](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-iolewindow-getwindow)
- [IOleInPlaceObject](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nn-oleidl-ioleinplaceobject)
- [SetFocus](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setfocus)
- [SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)
- [MOUSEINPUT](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-mouseinput)
- [KEYBDINPUT](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-keybdinput)
- [IOleInPlaceActiveObject::TranslateAccelerator](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-ioleinplaceactiveobject-translateaccelerator)
