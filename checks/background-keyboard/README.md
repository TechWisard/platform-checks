# Background keyboard contract

This opt-in isolated Windows API test reuses the existing owned-account child
session fixture. The ordinary window experiment must first pass its unchanged
identity, frame, pointer, keyboard, message-observer and cleanup checks. It has
already delivered eight random decimal characters and one click to the child.

Before Connect, only this opt-in mode reads the existing AdvancedSettings9
`allowBackgroundInput` as an exact Automation LONG, writes LONG 1 and requires
an exact LONG 1 readback. The documented property permits the client to accept
input without focus. The experiment logs initial/requested/readback scalars
and reads the same settings object again immediately before SendKeys, between
its existing ownership/foreground checks. Wrong types, COM errors or changed
values reject the attempt before input. It performs no focus change or retry
to compensate for a failed check. Ordinary modes never access this property.

This tests a documented configuration hypothesis for the previously observed
E_FAIL; it does not identify the internal cause of that generic HRESULT.

If the ordinary window path fails its initial parent-target guard, diagnostic
evidence identifies the first actual failed predicate and the checked mask in
the original short-circuit order. Later operands are null; focus and geometry
checks that have not run are explicitly marked not reached. Recording uses the
already evaluated booleans and adds no window queries, activation or input.
The original failure stage/code remains unchanged if diagnostic recording fails.
The job budget is 15 minutes; the actual experiment step retains its 8-minute
limit and all per-stage deadlines and cleanup gates.

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

For a failed background phase, the optional witness records at most 32 of its
own key-up messages, with a saturating dropped counter. Metadata includes the
ordinal, normal/system message kind and bounded repeat/extended/reserved/
context/previous/transition flags. Digit and all other printable or unknown
virtual-key and scan codes are redacted. Only the explicit modifier/lock
allowlist retains codes, and a scan is retained only for an explicitly allowed
VK/scan pair. The parent reapplies both allowlists before logging.
Category values are 0 (other redacted), 1 (digit redacted), 2 (modifier),
3 (lock), 4 (VK_PACKET), 5 (VK_PROCESSKEY), 6 (zero) and 7 (0xFF). The four new
fixed classes retain neither VK nor scan values. In particular, a packet scan
can encode character data and is always redacted. The optional metadata shape
has no role in receipt acceptance, and
malformed diagnostics are reported best effort without replacing the failure.
Ordinary modes do not collect this metadata or add it to their reports.

The failure event also records only a nullable expected-text equality boolean.
Comparison is eligible only after one send attempt and a nonce-bound report
newer than the accepted baseline; otherwise it is not performed. Neither the
expected nor received text is logged. This comparison does not imply acceptance:
all original counts, flags, UI guards, quiet interval and cleanup gates remain.
The failure event includes existing character/error counters, received length,
aggregate decimal/hex-letter counts and a fixed difference class/count. Its
comparison inspects at most 16 stored characters and emits no character values,
positions, text prefixes, hashes or nonce. These scalars distinguish invalid
characters discarded by the witness from a same-length valid-hex mismatch.
The metadata describes observed messages; it does not attribute their source
or prove which operation caused an extra release. Diagnostic collection adds
no input, focus changes, window queries, retries or replay.

`ContractTests` run against the actual compiled harness before Windows use.
They reject malformed ABI metadata, invalid array sizes/scan codes, stale or
incorrect child receipts, wrong counts, changed UI ownership and missing
health checks. They also execute the actual background-setting helper with
controlled getters/setters, checking opt-in, exact LONG type and value,
readback changes and failures before the send gate. They do not claim to
execute the Windows APIs.

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
- https://learn.microsoft.com/en-us/windows/win32/termserv/imstscadvancedsettings-allowbackgroundinput
- https://learn.microsoft.com/en-us/windows/win32/inputdev/wm-keydown
- https://learn.microsoft.com/en-us/windows/win32/inputdev/wm-keyup
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-mapvirtualkeyexw
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook
- https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwinevent
