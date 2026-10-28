# Owned child Search preparation

This optional experiment prepares the newly created, nonadministrator child
session used by `../child`. It addresses one observed obstruction: the fixed
Windows Search surface can remain in the foreground before the witness window
is created. The helper can send one Escape down/up pair to that exact surface.
The later frame and input experiments retain their independent acceptance gates.
An accepted preparation result does not establish that a frame is visible or
that input was delivered to the witness.

The hosted session workflow opts in by passing
`-ChildSearchPreparationProgram` to `../first-logon/run-prepared.ps1`, which
forwards `-ChildSearchHelper` to `../child/run.ps1`. The corresponding application
argument is `--child-search-helper PATH`. Ordinary child-harness invocations,
including the separate evaluation-guest path, do not enable this preparation.
The native helper has only one supported invocation:
`child_search_prepare.exe --allow-owned-child-search`.

## Receipt and ownership

The parent first creates the child account/session and verifies its actual
ownership. It then copies the helper into the existing witness sandbox and
creates `child-search-receipt.bin`. The receipt records the actual parent,
child and console session IDs, their different binary SIDs, an issue time,
an expiry exactly 90 seconds later, and an independent random 24-byte nonce.
The nonce is unrelated to the frame and input challenges. No frame palette,
input challenge or credential is passed to the native helper.

The parent explicitly sets itself as owner of the binary directory, copied
helper and receipt. Their protected ACLs grant the child read/execute access;
the parent, SYSTEM and administrators retain control. The helper opens the
fixed receipt beside its own executable, pins the directory and receipt
handles, rejects reparse points, extra links and unexpected lengths, and
decodes a maximum of 208 bytes. It verifies both actual owners and uses
`AccessCheck(MAXIMUM_ALLOWED)` with its own duplicated token to require read
access and reject write, append, attribute, deletion and ACL/owner rights for
the child on the receipt and directory.

The receipt's child SID must match the running process token. The token must
be nonelevated and have no Administrators membership, including deny-only
membership. The process must be in the recorded nonzero child session, that
session must be `WTSActive`, and its current thread must use the active
`Default` input desktop. The recorded parent console session must remain the
active console. These are actual child-session checks; the helper does not
pretend that the child owns the console or rely on a fabricated hosted-runner
environment variable. Time, desktop and ownership checks are repeated before
the action.

This receipt provides a narrow ownership boundary for an experiment on its
own disposable machine. It is not cryptographic attestation against an
administrator who controls that machine.

## Guarded action

The candidate must be the visible foreground root in the same child session,
with exact class `Windows.UI.Core.CoreWindow`, package family
`MicrosoftWindows.Client.CBS_cw5n1h2txyewy`, and application ID
`MicrosoftWindows.Client.CBS_cw5n1h2txyewy!CortanaUI`. A process handle pins the
observed owner. An absent exact class or package/application match produces
`not_needed` without sending input. API failures and ambiguous observations
produce `failed`.

For the exact target, two fresh UI Automation observations must identify the
same HWND, process and root element. Each must report a visible, nonpassword
Window element with exactly one visible, nonpassword match for the fixed
name predicate `Search`, belonging to that process. The helper does not read
arbitrary Name, Value or Text values, query text, account fields or passwords.
UI Automation automatic focus is disabled. There is no privacy-page action
in this helper.

Immediately before `SendInput`, the helper rechecks the target and records
the queue and asynchronous high bits for the fixed modifier/Escape key set.
All must be clear, and `GetKeyboardState` must succeed. It sends at most one
batch containing Escape down and up. A partial one-event insertion permits
one compensating key-up event only; the functional result still fails. The
helper observes the Escape high bit after its release event and reports key
cleanup separately. A zero asynchronous state is not proof of a physical
key's state or an atomic guard against concurrent human input.

After a complete pair, the helper observes only the pinned Search HWND. A
fresh verified loss of foreground, or hiding/destruction, accepts the action
as `prepared` with stage `pinned_search_left_foreground`. The report separately
records `target_exists`, `target_visible` and `target_foreground`. A Search
window may continue to exist and be visible after leaving the foreground;
the helper does not claim that it was destroyed, that all Search surfaces
are absent, or that an ordinary desktop has been proved.

## Ordering, deadlines and evidence

The scheduled child process writes its own identity evidence and runs this
preparation before constructing the palette, witness Form or input observer.
The managed wrapper gives the native process a 15-second budget with bounded
stdout/stderr reads. Its cleanup allows up to three seconds to stop and reap
only that owned process tree and two seconds to complete its output tasks.
The native code checks a 10-second budget, requests one-second UI Automation
connection and transaction timeouts, observes release for at most 250 ms and
the pinned target for at most three seconds. A native/provider call can still
block; the managed process deadline and the parent experiment deadline remain
independent protections. Stopping a process does not prove that every injected
input event or remote provider action has completed.

The native result is one bounded `child-search-prepare/v1` JSON object. The
managed wrapper rejects unknown, missing or duplicate keys, wrong types,
out-of-range counts, contradictory flags and an incorrect receipt nonce. It
writes a separate `witness-preparation.json` bound to the parent's witness
nonce, identity digest, actual child session and preparation nonce. The parent
revalidates child ownership and this report before permitting its frame check.
Public event output omits the binding nonces and identity digest. Status,
fixed stage names, HRESULTs, counts and observed flags remain available.

When preparation is requested, `run.ps1` requires verified cleanup and
`child_search_render_probe_eligible` before accepting the later functional
result. `child_search_preparation_verified` retains its strict meaning: only
the native `prepared` or `not_needed` outcome with exit zero can set it true.
`not_needed` means only that the exact eligible Search target was not observed;
independent frame validation still decides whether the witness is visible.

### Rendering after an unresolved foreground observation

The managed fixture also permits creating its own witness after one narrowly
defined observation: the native helper exits with `failed`, stage
`search_target_still_foreground`, and HRESULT `E_UNEXPECTED` (2147549183), after
three seconds of target observation, while all ownership and input-cleanup
requirements still hold. This does not change the native helper or its exit
code. It does not send another key, invoke another UI element, hide the target,
or claim that the Escape pair was delivered.

The new path requires the same valid receipt and nonce, protected owners and
ACLs, exact nonadministrator child identity, active child and Default input
desktop, unchanged console parent, two matching UI Automation observations,
and freshly rechecked target owner. Both key-state masks must be zero. Exactly
one two-event Escape batch must have been inserted, with its release observed,
no compensation call or Win32 error, and successful native cleanup. The final
pinned target must still be valid, exist, be visible, and be foreground. The
report must contain at least two target observations, an elapsed time from
3000 through 9999 ms, and successful COM cleanup. Every other failure remains
ineligible.

The managed wrapper separately requires native exit code exactly one, completed
bounded output, a reaped owned process, successful process cleanup, and no
managed error. A version-two `witness-preparation` envelope records the native
failure alongside `native_foreground_unresolved` and `render_probe_eligible`.
The parent revalidates the exact native and process evidence and checks its
existing child/witness ownership before allowing a frame capture.

For this path, `child_search_preparation_verified` stays false and
`child_search_foreground_unresolved` records the pre-witness observation.
Only `child_search_render_probe_eligible` becomes true. The existing witness
then makes its single own-window presentation request and reports what
actually happened. No foreground or presentation retry is added.

The captured nonce-dependent frame, child identity/token, and normal-window
input checks remain unchanged. The runner still requires their actual results
and all session/account/input cleanup results. Eligibility alone cannot
produce a frame/input success or turn a nonzero harness exit into success.

## Build and contract checks

Configure this directory separately with CMake 3.20 or newer. On Windows it
builds `child_search_prepare` and `child_search_receipt_tests`; MSVC and MinGW
builds enable strict compiler diagnostics. On other systems the portable
receipt decoder and its tests can be built without Windows APIs.

The portable tests cover a valid receipt, every truncation of that fixture,
extra bytes, null input, invalid sessions/console, expired and future receipts,
invalid lifetimes and SID layouts, equal SIDs, a zero nonce, wrong magic/version
and preservation of a previous result on rejection. These are parser tests.
They neither execute the native helper nor verify Windows ACLs, tokens,
desktops, UI Automation or injected input.

This helper is an independent disposable-session experiment. It does not
implement or establish physical keyboard/mouse separation, GPU/output
assignment, driver compatibility or a deployable multi-seat product.

## API references

- [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
  defines token-based access evaluation and the `MAXIMUM_ALLOWED` result.
- [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
  describes querying object ownership and discretionary access controls.
- [SendInput](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput)
  documents the inserted-event count, existing keyboard-state caveat and
  integrity-level restrictions. Successful insertion alone does not prove
  witness delivery.
- [GetAsyncKeyState](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate)
  specifies the high-bit observation and explains why zero may also indicate
  an API access failure.
- [GetUserObjectInformationW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getuserobjectinformationw)
  defines the `UOI_IO` and `UOI_NAME` desktop observations used here.
