# Disposable first-logon preparation

This is a separate, explicitly opted-in CI helper. It invokes only the exact
privacy page previously observed on an owned disposable GitHub-hosted Windows
runner. It is not a general OOBE, login, activation, credential or popup handler.
It creates no windows and performs no action unless the fixed checks below
succeed. It does not change the original read-only presentation probe.

## Native helper contract

`first_logon_prepare.exe --allow-disposable-privacy-preparation` requires all
three hosted Windows environment markers and a nonzero active console session
matching the calling process. It verifies an active `Default` input desktop.

For an actionable page, the foreground root must have:

- The exact class `Windows.UI.Core.CoreWindow`.
- Package family `Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy`.
- Application ID `Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App`.
- A process and thread belonging to the caller's active session, with the
  process handle retained through the operation.
- At least one exact, visible text heading `Choose privacy settings for your
  device` (bounded at eight matches).
- Exactly one visible, enabled, non-password `UIA_ButtonControlTypeId` element
  with `AutomationId` equal to `OobeSettingsAcceptButton` and an Invoke pattern.

UI Automation searches only that verified window. Conditions filter the fixed
heading and button in the provider; unrelated names and values are not read.
The helper obtains a second fresh page snapshot, compares button identity, and
rechecks foreground, process, thread, package, application ID and active session
immediately before the first normal `IUIAutomationInvokePattern::Invoke` call.

No switch values are toggled. The first action invokes the fixed privacy-page
button; its current label is observed rather than assuming that its ID means
the page has completed. A missing/changed page, a duplicate or disabled
button, an owner change or an API failure stops the helper. The only possible
second action is the separately verified exact Accept transition below. There
is no generic retry, fallback button, key injection, focus request, process
kill or window close directed at Windows UI.

After the permitted action or actions, the helper waits for the observed page HWND to become
hidden or cease to exist. It also requires the active Default input desktop,
an actual same-session Explorer shell and an ordinary foreground: that shell,
a known Explorer window class in its process, or the helper's own associated
console. Five consecutive observations, separated by 250 ms, are required.
Unknown foreground UI is not treated as ordinary desktop readiness.
The wrapper uses `CreateNoWindow=true`; consequently this helper normally has
no associated console HWND. A pre-existing runner console in the foreground
may therefore produce `ordinary_desktop_timeout` rather than `not_needed`.
The helper does not broaden its ownership rule to guess that console's identity.

If the initial foreground is not the CloudExperienceHost package, **no UI action
is performed**. `not_needed` is returned only after the same ordinary-parent-
desktop checks. It makes no assertion that a future child session has no pages.

The native helper uses an MTA thread without its own windows. UI Automation
connection and transaction timeouts are one second. The overall observation
budget is 32 seconds, with the ordinary-desktop wait ending at 29 seconds to
reserve three seconds for a post-Invoke content observation. A synchronous provider may still block, so the wrapper
adds a 40-second process wait and at most one three-second stop wait, within a
45-second outer bound. Only the process tree created by that wrapper is stopped.
Forced termination is reported as failure and cannot prove native cleanup.

Output consists only of a bounded JSON record with fixed status labels, numeric
counts and HRESULTs, and booleans. The only variable UI text emitted is the
bounded safe ASCII label of the fixed button on the verified privacy page.
No arbitrary UI text, user/domain/SID,
credentials, window handles, screenshots, or process paths are emitted. The
exact Explorer image path is used transiently only to check the basename and
its buffer is cleared. Arbitrary UI values or credential fields are not inspected.

Exit 0 means `completed` or `not_needed` with the stated parent-desktop
observations and cleanup. Exit 1 means the preparation did not establish those
conditions. Remote pixels, input channels, session functionality and physical
isolation are always reported as unverified.

## Policy lifetime and strict downstream gates

`run-prepared.ps1` additionally requires
`-AllowDisposablePrivacyPreparation`. Before the helper and before any fresh B
account, it reads both existing policy values, their exact Registry64 kinds,
and unexpanded data; then sets only:

| Registry64 key under HKLM | Value | Temporary DWORD |
|---|---|---:|
| `SOFTWARE\Policies\Microsoft\Windows\OOBE` | `DisablePrivacyExperience` | 1 |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | `EnableFirstLogonAnimation` | 0 |

Both snapshots are completed before either write. The wrapper verifies writes
and runs the unchanged independent native window calibration after every
completed, parsed helper result, including a preparation timeout. The original
helper status and `parent_preparation_verified` observation are retained.
The independently measured display is the downstream readiness gate: the
wrapper requires the same nonzero session, successful screen capture, both
9-point own-root masks equal to 511, all eight unpredictable color counts at
least 80 within tolerance 3, and verified own window/class/GDI cleanup.

Only a helper success or the exact observed `ordinary_desktop_timeout` with
`WAIT_TIMEOUT`, `wait_guard=3`, verified Explorer shell, fresh final active own
console/Default input desktop, verified cleanup and correct action ownership
is eligible for this gate. Other helper errors still block the child. The
zero-action branch requires that the target was not initially foreground; the
one-action branch requires all original heading/button/root/owner checks and
successful Invoke. The two-action branch additionally requires both fresh
exact-label/page observations, final ownership and button identity, a delay
between 1000 and 6000 ms, and successful second Invoke. A known Accept label
before the first action excludes this branch. `parent_display_verified` is distinct from setup completion,
which is not claimed. Failed native calibration always blocks the child.
The two policy values are rechecked
before starting it with `-AlternateTestAccount -TestDirectInput`.

The calibration and child runner execute as owned PowerShell subprocesses, so
their `exit` statements cannot leave the policy wrapper's `finally` scope.
That one `finally` covers all preparation, calibration and experiment failures.
Each policy restoration runs independently. Original values are restored with
the original kind and unexpanded contents; originally absent values are
deleted. Fresh readback must match before `policy_values_restored` becomes true.
Snapshots and their contents are not printed or written to files.

Restoration concerns the two named values. An originally absent leaf registry
key may remain empty; the script never deletes a registry tree or unrelated
values. Native test/account cleanup remains the existing harness's separately
reported responsibility. External runner loss can prevent `finally`; absence
of a final restoration report is not evidence of cleanup.

The workflow disables cancellation of an earlier running job on push
(`cancel-in-progress: false`). It does not alter authentication, certificates,
RDP security, licensing, activation, Secure Boot, TPM, or driver settings.

## Workflow integration

The session-contracts workflow builds this helper separately and encloses
the existing native calibration and child experiment in the prepared wrapper.
The prior diagnostic run [40699423335](https://github.com/TechWisard/platform-checks/actions/runs/40699423335)
proved a usable own-window display on Server 2025 despite Windows Terminal
remaining foreground, while Windows 11 ARM failed the same independent
calibration. That measured difference motivates the display-based gate.
This source revision still requires a Windows runtime execution.

## Primary contracts and observed-page provenance

- Exact page observation: [run 40695413656, job 122840761797](https://github.com/TechWisard/platform-checks/actions/runs/40695413656/job/122840761797), commit `da86cbf68d3303e70d4d46525f4881bd71bb0750`.
- Exact post-action button observation: [run 40701537180, job 122862375190](https://github.com/TechWisard/platform-checks/actions/runs/40701537180/job/122862375190), commit `fbe0c89d9725407404129a894dbc8d154452ec07`.
- [UI Automation Invoke](https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationinvokepattern-invoke).
- [UI Automation threading](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-threading).
- [Read-only UI Automation Name](https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationelement-get_currentname).
- [Unicode 16.0 White_Space](https://www.unicode.org/Public/16.0.0/ucd/PropList.txt) and [General_Category=Cf](https://www.unicode.org/Public/16.0.0/ucd/extracted/DerivedGeneralCategory.txt).
- [DisablePrivacyExperience](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#disableprivacyexperience).
- [EnableFirstLogonAnimation](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#enablefirstlogonanimation).

The button ID and heading are runtime observations from that page, not a claim
that every Windows build or language exposes this UI contract. A mismatch fails
without an alternative UI action.

## Independent wait observations

After the first actual preparation attempt timed out, each ordinary-desktop
guard now records its own observation before later guards can return early.
Shell presence and Explorer identity, foreground category, associated-console
presence, and the original target HWND's existence/visibility are separate
fields. `DWMWA_CLOAKED` is read only for that original observed target; its
numeric HRESULT and flags are diagnostics and do not alter the readiness gate.
No unknown window class text or UI name is emitted.

`wait_guard`: 0 = observation not yet completed; 1 = shell absent; 2 = foreground
absent; 3 = foreground outside the existing ordinary categories; 4 = original
target still visible; 5 = owner/foreground changed on final recheck; 6 = ready
poll. Other API errors retain their explicit failure stage.

`foreground_class_category`: 0 = absent/unreadable; 1 = Progman; 2 = WorkerW;
3 = CabinetWClass; 4 = ConsoleWindowClass; 5 = CASCADIA_HOSTING_WINDOW_CLASS;
6 = Windows.UI.Core.CoreWindow; 7 = ApplicationFrameWindow; 255 = unclassified.
These foreground classifications authorize no additional action. The
32-second native budget and the helper's foreground/absence observations remain.
The downstream wrapper now uses the separately verified display gate described
above; the existing child frame and direct-input assertions are unchanged.

## One observed Accept transition

The completed Windows 11 ARM run cited above measured the same verified
privacy heading and unique enabled onscreen button after one successful Invoke.
The button's safe normalized Name was exactly `Accept these privacy settings`.
The pre-action name failed the safe output filter, so a More-to-Accept sequence
is not established and the helper does not claim one.

This revision permits at most two normal Invoke calls in total. If the first
button's normalized label was already `Accept` (classified category 3) or the
exact observed full phrase, the second call is prohibited. Otherwise, after at
least one second, a single early inspection may consider that exact phrase.
The original pinned target must still be the visible foreground root with the
same process, thread, session, class, package and AUMID. A disappeared or
non-foreground target causes no second action and continues to the ordinary
desktop/display checks.

The prospective second action obtains two fresh full privacy-page snapshots.
Both require the exact visible heading and unique enabled visible non-password
fixed-ID button, matching UIA root HWND/process and an Invoke pattern. Both
normalized button labels must match the entire observed phrase, case
sensitively. A substring match is never used. CompareElements must confirm the
same button, and the full pinned target owner/foreground check runs immediately
before the second call. The call must begin before six seconds have elapsed
since the first completed Invoke and before the ordinary wait deadline.

There is no polling action loop and no third call. A nonmatching label causes
no action. A missing/changed eligible page or API error fails safely. A page
that exposes Accept later than this single early inspection may remain
unhandled; no success is inferred. The 32-second native and 40-second wrapper
budgets, policy restoration and independent display/frame/input gates remain.
The `second_action` record reports both page/label/owner checks, observed delay,
button identity, attempted call and HRESULT; it does not replace the first
action's original evidence.

## Bounded post-Invoke observation

After the wait, one fresh UIA observation can inspect only the original
CloudExperienceHost root with its process handle still held. Session, process,
thread, package, AUMID, class, visibility and foreground are checked before the
read and rechecked after it. Content is discarded if ownership changes.
The UIA root's native HWND and process must also match. A closed or changed
target produces an unavailable diagnostic; it does not trigger another action.

Provider conditions search only fixed visible, non-password text headings and
the known non-password button ID. The post-read button search includes disabled
and offscreen states so those changes are observable. At most one matching
button may expose metadata, and its label is read only while the exact visible
privacy heading remains. There is no enumeration of arbitrary element names.
The original verified button's label is also read immediately before the final
action ownership recheck. This final post-wait observation never triggers an action.

Raw label length is limited to 128 UTF-16 code units; no oversized prefix is
emitted. Unicode White_Space is collapsed and trimmed, Unicode format code
points are removed, and all other non-ASCII characters are rejected. The safe
ASCII fallback permits letters, digits, spaces, hyphens, apostrophes,
parentheses, question marks and exclamation marks only, excluding controls,
quotes, URL/email/path punctuation. Category 1=More, 2=Next, 3=Accept,
4=Continue, 5=Done, 255=another safe label, 0=not classified/available.
The full raw BSTR is cleared before release.

`post_invoke.heading_counts` uses these fixed positions; -1 means unread and
zero means the completed query found no visible match:

| Index | Exact fixed heading |
|---:|---|
| 0 | Choose privacy settings for your device |
| 1 | Privacy settings |
| 2 | Hi |
| 3 | Just a moment... |
| 4 | Just a moment |
| 5 | Getting things ready |
| 6 | We're getting things ready for you |
| 7 | This might take a few minutes |
| 8 | Let's finish setting up your device |
| 9 | Something went wrong |
| 10 | Microsoft account |

Read errors and the deadline are reported separately under `post_invoke`.
A successful UIA Invoke, a known label, or a heading count does not prove setup,
remote frames or input. The two-Invoke maximum and exact separate-transition
guards remain in force for this revision.
