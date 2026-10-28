# Windows child-session contract experiment

An independent Windows API experiment, not a multiseat product. It attempts to
create a real local RDP child session while keeping its parent session active,
then verifies that pixels from a known process in that child reach the visible
ActiveX client. No proprietary product code or third-party implementation is
included.

## What is and is not being proved

A successful run must observe all of the following, followed by successful
cleanup:

1. The caller has an active interactive Windows session outside Session 0.
2. No child session exists for that parent before the attempt.
3. The documented RDP ActiveX control accepts `ConnectToChildSession=true` and
   `Connect()` leads to a newly observed child session ID.
4. The parent and child are both active, with a connected RDP control.
5. Windows resolves the child to the expected SID: the parent account in the
   default mode, or the exact newly created account in the opt-in account fixture.
   No account names or SIDs are emitted. Identity is measured, not inferred from
   two different session numbers or the requested RDP user name.
6. A temporary Task Scheduler task starts this program's witness mode in that
   exact new session, using its existing interactive token and no password.
7. The witness reports its real session ID and a per-run salted identity digest.
   The parent checks both and observes eight unpredictable colors rendered by
   the witness through the ActiveX client. Desktop screenshots are never saved.
8. The temporary task and created child session are removed, the previous
   child-session enabled state is restored, the parent is still active, and the
   active console session ID remains unchanged.

`native_multiseat_verified` and `physical_input_isolation_verified` stay false.
An active child session with the same account is **not** proof of separate
accounts, physical keyboard/mouse isolation, independent locking, physical GPU
output ownership, 3D performance, or general application compatibility.

If the child's resolved account differs from the expected identity, the program
records that observation and fails before scheduling the witness. Its helper can
run only in its recorded new child with the exact expected interactive token.

## Optional owned-account fixture

`-AlternateTestAccount` explicitly selects an additional test on a fresh
GitHub-hosted Windows VM. The default executable path creates no account. This
fixture requires an already elevated parent, the hosted-runner environment
markers, and a matching system Windows Desktop runtime. Environment markers
protect against accidental invocation; they do not certify an arbitrary host.

The fixture creates one unique ordinary local account with a fresh random
40-character password. It never adopts an existing name, changes group
membership or logon rights, or obtains an existing user's password. The created
account must have a different SID and no Administrators membership. Credentials
are supplied only to the documented RDP properties from zeroed temporary native
buffers and a short-lived SecureString; they are not in arguments, environment,
reports, files, or Task Scheduler.

The child must actually resolve to that created SID while the parent remains
active in the same console. Only then is the witness copied to a new protected
directory and launched with `TASK_LOGON_INTERACTIVE_TOKEN`, `TASK_RUNLEVEL_LUA`,
and `TASK_RUN_USE_SESSION_ID | TASK_RUN_USER_SID`. B can read/execute the three
test payload files and write only its result directory. No system, window
station, desktop, profile, or repository ACL is changed. The witness reads its
native token groups, including deny-only entries, to reject administrator tokens.

The created task instances must actually stop before deletion. The owned child
and RDP control must be gone before deleting the exact original account SID;
unexpected sessions or reused names are left untouched. `NetUserDel` removes
the account, not a possibly created profile. Discard the VM after every run.
Forced termination leaves cleanup unverified. The existing child-session limits
apply even if a different-account result succeeds.

Account cleanup inventories both WTS session IDs and states. It does not query
a user SID for a `WTSListen` record: Microsoft defines that listener as having
no logged-on user and not being convertible to a regular client session. A
7022/not-found response invalidates the entire snapshot and starts a fresh
bounded pass. A successful pass must also have a matching second inventory;
access errors and unresolved identities still block deletion. At most four
passes are attempted, with numeric inventory diagnostics and no account names.

```powershell
# Fresh disposable GitHub-hosted Windows VM only:
.\run.ps1 -ResultsDirectory "$env:RUNNER_TEMP\account-contract-new" -AllowEnableChildSessions -AlternateTestAccount
```

## Optional direct-input delivery experiment

`-TestDirectInput` additionally requires `-AlternateTestAccount`. No input is
sent until the unchanged parent frame challenge and the distinct account B
identity have actually passed. The witness first reports an empty input
baseline, its own foreground/focus, input desktop and measured geometry.

The test sends one mouse move through the documented RDP input sink. A new
actual `WM_MOUSEMOVE` in the witness must confirm the exact physical point and
own root before the single left down/up is allowed. Then eight independent
random hex characters, known only to the parent, must arrive as real witness
character messages. Extra/repeated/invalid input fails. A quiet interval and a
newer heartbeat after its end are required; a stale report is not success.

The parent observes its own UI-thread keyboard/button messages without
suppressing them and repeatedly checks its cursor. Any observed parent effect
fails. This is bounded evidence about the selected RDP connection, not physical
device isolation or observation of every parent process. Both physical/native
multiseat fields stay false. COM method/enum signatures are checked against the
installed Microsoft type library; successful HRESULTs alone do not pass.

## Run only in an isolated disposable test machine

Requirements: Windows with the desktop RDP ActiveX control, .NET 8 SDK and the
matching Windows Desktop Runtime, an active logged-on interactive parent, and
permission to create the current user's temporary interactive scheduled task.
The Windows user and process identity must match.

Build and run in PowerShell:

```powershell
.\run.ps1 -ResultsDirectory .\results\attempt-1 -AllowEnableChildSessions
```

Without `-AllowEnableChildSessions`, a disabled child-session feature is reported
as an unsupported environment; it is not enabled. With that explicit flag the
experiment calls `WTSEnableChildSessions(true)` only if necessary and restores
the original state after removing its child. Enabling may require elevation;
the program does not elevate itself. A pre-existing child is never attached,
disconnected or logged off.

The script uses the SDK already selected by the environment; CI should pin its
SDK and runner image and retain their exact versions with the JSON report.
The project has no NuGet package references. A Windows build produces the
apphost for the build environment's architecture. On ARM64, record whether the
selected `dotnet` process/runtime is native ARM64 or emulated x64; both OS and
process architectures are present in the report.

Direct invocation:

```powershell
dotnet build .\SessionContractExperiment.csproj -c Release -o .\bin\experiment
.\bin\experiment\SessionContractExperiment.exe --output .\results\attempt-2.json --allow-enable-child-sessions --timeout-seconds 120
```

The output file must be new. No arbitrary credential input, saved passwords, authentication
policy changes, certificate-validation bypasses, firewall changes, RDP listener
reconfiguration, system-DLL changes or driver installation are performed. An
authentication prompt, certificate failure or policy block must produce failure
or timeout. The process never tries to fill or dismiss credential dialogs.

Both experiment windows are borderless and bounded by the primary monitor.
Each makes one request to present its own window with TopMost, BringToFront and
Activate. Actual foreground/root ownership, screen bounds and DWM cloak state
are measured; a successful method return is not proof of visibility. No focus
retry loop, foreign-window changes, desktop switch or display/DPI setting change
is used. The child's screen-color observations supplement the unchanged parent
frame challenge; they cannot make that challenge pass on their own.

The normal path has a finite connection/frame deadline, with separate bounded
cleanup checks for task instances, logoff and control disconnection. The wrapper
bounds the whole process to the requested deadline plus 75 seconds. A forced process termination
is reported as a failure with cleanup unverified. A CI job also has an outer timeout
and discard its VM after an abnormal process crash or forced cancellation;
cleanup cannot be claimed after a killed process. Such an outcome is not a pass.
The temporary helper has its own 150-second lifetime and its scheduled task has
a three-minute execution limit.

## Exit codes and evidence

| Exit | Meaning |
| --- | --- |
| `0` | Actual simultaneous child session and rendered challenge verified, with cleanup complete |
| `1` | Attempt or cleanup failed; see stage and HRESULT/Win32 codes |
| `2` | Internal witness could not verify its assigned interactive session |
| `64` | Invalid arguments or existing output file |
| `77` | Unsupported current environment or intentionally untouched existing child |

CI must distinguish `77` from a successful functional test. A successful build,
API export, property setter or `Connect()` return alone is never a functional
pass. HRESULTs and stage names are retained; exception messages that might
contain account names, paths or other personal information are omitted.

The one witness task uses a random name and `TASK_CREATE`, so it cannot replace
an existing task. The app has no startup triggers. Cleanup requires a fresh link
from the parent to the observed new child before logging it off. The ActiveX
control is disconnected after that logoff. A cached numeric session ID alone
never authorizes logoff because Windows can reuse IDs. Lost ownership produces
`cleanup_failed`; the program does not terminate an unrelated session to obtain
a successful cleanup result. It never logs off the parent or a session present
at baseline.
The per-run witness report is temporary and removed during cleanup. The final
JSON contains identity equality booleans, session IDs, timing, architecture,
operation codes and color counts, with no usernames, SIDs or passwords.

The RDP event interface is verified against the installed type library. A real
disconnect records its numeric reason and queries the read-only extended reason
before intentional cleanup. `GetErrorDescription` supplies the client's bounded
diagnostic text. `AuthenticationLevel=1` requires successful server authentication;
CredSSP is enabled and credential prompting is disabled for this connection.

The wrapper also emits bounded read-only environment snapshots: two RDP services,
selected numeric registry settings, and listener-port/address classes. Following
the process it reads at most 16 Security 4625 events from that attempt's time
window, retaining only numeric status/substatus, logon type, timestamps, record
IDs and fixed package/address classifications. No usernames, SIDs, domains,
messages, IP addresses or full event XML are emitted. These are explicitly
`time_window_only` observations, not proof that every event came from this test.
Missing auditing or denied access remains unavailable/no-events; audit policy
is never changed. These diagnostic records cannot make a failed test pass.

The same time window is read from three already enabled RDP Operational logs,
up to 16 events per channel. Only event metadata and explicitly allowed numeric
error/state fields are emitted. Disabled logs stay disabled. These records also
have `attribution=time_window_only`.

The witness's identity report is separate from a bounded, atomic
`witness-render/v1` report. The latter records Shown/Paint observations, its own
window geometry and desktop categories, UOI_IO results and aggregate color
counts from its own client area. The parent verifies its nonce/session/identity
binding and excludes the nonce/digest from published observations. Post-identity
UI failures are recorded numerically and terminate the witness without an error
dialog. No image or screen text is written.

Parent capture still uses one `SourceCopy` of the same ActiveX region. `LockBits`
and sampled-row copies replace per-pixel interop calls. The 4-pixel sample step,
RGB tolerance 3 and minimum 80 samples for all eight colors remain unchanged.
First, periodic (at most once per 10 seconds), and final observations include
color counts, minimum distances, virtual/client geometry, DPI and window
visibility/ownership measurements. None of those diagnostic fields substitutes
for receiving the unpredictable frame challenge. This geometry probe targets
modern Windows 10/11 and Server 2016+ APIs; the CI matrix records its actual OS.

The read-only coverage probe also records native topmost state and owner
process/session equality for the foreground and the same nine sampled roots.
An owner must be a different process in the current session, with successful
queries and an unchanged thread/process pair on recheck, before an otherwise
`other` category can include `other_process_base_name` (at most 128 characters)
or `other_window_class_name` (at most 256). Already classified and own windows
keep their fixed categories without additional names. These names are
diagnostic labels, not authenticated component identities.

Names accept only ASCII letters, digits, space, dot, underscore, hyphen and
parentheses; window classes additionally accept `#`, `:`, `;`, brackets and
braces. Invalid, over-limit, failed, potentially truncated or ineligible names
are null/unknown; strings are never altered or clipped into different names.
Only the targeted owner's existing `PROCESS_QUERY_LIMITED_INFORMATION` image
query is used. Its temporary full-path buffer is cleared after taking the
basename; full paths are neither saved nor emitted. No process inventory,
command line, window title, account data or extra process rights are requested.
Class buffers are also cleared. No foreign window is activated or changed.

For a same-session `WWAHost.exe` covering window, the same limited-information
process handle also queries `GetPackageFamilyName` and
`GetApplicationUserModelId`. This distinguishes the generic host from the
application it hosts. Each query uses a fixed 257-character buffer; only a
successful, NUL-terminated identity of at most 256 ASCII letters, digits,
periods, underscores, hyphens or exclamation marks can be reported. Buffers are
cleared and identities are emitted only after the window-owner recheck.
Neither process command lines nor application URLs or window text are read.
These labels are diagnostics, not authentication or proof of a particular UI.
Owner checks remain sequential observations rather than an atomic lifetime
guarantee, and these diagnostic names cannot make the frame challenge pass.

`EnableFrameBufferRedirection` is requested as a documented optional loopback
optimization. Its accepted setting does not prove that the optimized transport
was negotiated, and no performance claim follows from this experiment.

## Documented limits of the mechanism

Microsoft documents one connected child session per system. It depends on a
parent session and ends when its parent ends. It cannot be locked and has no
independent logon screen. Those limits already prevent full multiseat parity.
The documentation describes automatic child logon, but local authentication
policy may still require credentials. The experimental result must state the
actual behavior of the tested OS build.

Microsoft Power Automate uses child sessions for a parallel desktop on Windows
10/11 Pro or Enterprise, which establishes a real supported use of the API.
It does not establish multiple independent local users, physical device
ownership, or broad application/game compatibility for this experiment.

## Primary API sources and provenance

All implementation code was written for this independent test. Documented names,
identifiers and contracts are from these Microsoft references:

- [Child Sessions](https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions)
- [WTSEnableChildSessions](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenablechildsessions)
- [WTSGetChildSessionId](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsgetchildsessionid)
- [IMsRdpExtendedSettings](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpextendedsettings)
- [Extended properties](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpextendedsettings-property)
- [IMsRdpClient10](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclient10)
- [IMsTscAx::Connected](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscax-connected)
- [IRegisteredTask::RunEx](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-runex)
- [TASK_RUN_FLAGS](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_run_flags)
- [TASK_LOGON_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)
- [ITaskFolder::RegisterTaskDefinition](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-registertaskdefinition)
- [Power Automate picture-in-picture](https://learn.microsoft.com/en-us/power-automate/desktop-flows/run-desktop-flows-pip)
- [Server authentication level](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclientadvancedsettings4-authenticationlevel)
- [Disconnect events and codes](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscaxevents-ondisconnected)
- [Extended disconnect reason](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclient-extendeddisconnectreason)
- [NetUserAdd](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd)
- [NetUserDel](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserdel)
- [ClearTextPassword](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscnonscriptable-cleartextpassword)
- [GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
- [GetClassNameW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclassnamew)
- [QueryFullProcessImageNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew)
- [GetPackageFamilyName](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagefamilyname)
- [GetApplicationUserModelId](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getapplicationusermodelid)

The `IMsRdpExtendedSettings` method offsets, calling convention, HRESULT return,
BSTR/VARIANT-pointer parameters and direction flags are validated against the
machine's installed `mstscax.dll` type library before invocation. A missing or
unexpected type description fails the experiment instead of guessing a COM ABI.
