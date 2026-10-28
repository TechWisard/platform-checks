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
5. Windows resolves both session users to the same SID; no account names or SIDs
   are emitted. This comparison is a measured result, not an assumption that two
   sessions represent two different users.
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
output ownership, 3D performance, or ASTER compatibility.

If the child's resolved account differs from the parent, the program records
that observation, stops before scheduling the witness, and reports failure.
This experiment intentionally only launches its helper with the current user's
existing interactive identity.

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

The output file must be new. No credential input, saved passwords, authentication
policy changes, certificate-validation bypasses, firewall changes, RDP listener
reconfiguration, system-DLL changes or driver installation are performed. An
authentication prompt, certificate failure or policy block must produce failure
or timeout. The process never tries to fill or dismiss credential dialogs.

The normal path has a finite connection/frame deadline and an additional
20-second logoff verification window. The PowerShell wrapper bounds the whole
process to the requested deadline plus 45 seconds. A forced process termination
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

The `IMsRdpExtendedSettings` method offsets, calling convention, HRESULT return,
BSTR/VARIANT-pointer parameters and direction flags are validated against the
machine's installed `mstscax.dll` type library before invocation. A missing or
unexpected type description fails the experiment instead of guessing a COM ABI.
