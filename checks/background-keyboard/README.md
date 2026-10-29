# Background keyboard contract

This opt-in isolated Windows API test reuses the existing owned-account child
session fixture. The ordinary window experiment must first pass its unchanged
identity, frame, pointer, keyboard, message-observer and cleanup checks. It has
already delivered eight random decimal characters and one click to the child.

The added experiment then does the following:

1. Reads the exact installed `IMsRdpClientNonScriptable::SendKeys` metadata and
   validates its `HRESULT`, calling convention, vtable bounds, three parameters,
   directions and array element widths. The queried IID is
   `2F079C4C-87B2-4AFD-97AB-20CDB43038AE`; the slot is never guessed.
2. Creates its own small parent-session decoy window and activates it once.
   The decoy must own both foreground and keyboard focus. No request to focus
   the RDP window occurs during the subsequent keyboard experiment.
3. Installs read-only foreground/focus WinEvent observers and own-UI message
   filters. A transient focus/foreground departure, unexpected local keyboard
   or button message, cursor movement, or identity change rejects the test.
4. Makes exactly one `SendKeys` call with 16 entries: down/up for eight fresh
   random decimal digits. The challenge is generated only in the parent; it
   never reaches the child in a file, command line, digest or IPC message.
5. Requires the child's real WndProc report to match the complete 16-character
   receipt with exact new deltas of eight down, eight up and eight characters.
   The original single click is unchanged. A quiet interval and another fresh
   heartbeat must follow delivery. `S_OK` alone is not a delivery result.
6. Removes the observers, releases the separately queried COM reference and
   destroys only the owned decoy, then uses the fixture's existing session,
   account, task and file cleanup.

Only `--test-sendkeys --test-window-input` enables the second phase. The witness
keeps its existing eight-character cap in every original mode; this one opt-in
permits sixteen. The wrapper checks strict typed flags and a distinct terminal
status. Failed or unknown calls are never replayed.

`ContractTests` run against the actual compiled harness before Windows use.
They reject malformed ABI metadata, invalid array sizes/scan codes, stale or
incorrect child receipts, wrong counts, changed UI ownership and missing
health checks. They do not claim to execute the Windows APIs.

The workflow runs only on a fixed Windows 11 ARM hosted runner, on manual
dispatch or a change to `run-request.json`. Its credential/account scope is the
same disposable-hosted-runner scope as the existing session fixture. It never
reads or uploads a product repository or full product executable.

Passing proves the documented keyboard call delivered in this fixture while
the owned decoy held the parent's foreground. The first phase still uses the
normal parent input queue; background mouse delivery, physical HID suppression,
multiple physical workstations and native full-product execution are untested.

Primary API contracts:

- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclientnonscriptable-sendkeys
- https://learn.microsoft.com/en-us/windows/win32/inputdev/wm-keydown
- https://learn.microsoft.com/en-us/windows/win32/inputdev/wm-keyup
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-mapvirtualkeyexw
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwinevent
