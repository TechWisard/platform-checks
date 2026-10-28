# Native event delivery observation

This standalone Windows test observes real callbacks from the installed Remote
Desktop ActiveX control. It is not a remote-desktop application, an RDP server,
an account/session launcher or a device-assignment tool. The source has not yet
been executed on Windows; local cross-compilation is compile/link evidence only.

## Exact experiment

The process requires a disposable GitHub-hosted Windows runner, a nonzero
session and an identity other than LocalSystem. It initializes a strict STA,
creates one hidden owned Win32/OLE host and checks that the loaded control
module is the System32 `mstscax.dll`. Its native interfaces and event signatures
are validated against that module's type library before use.

The test binds a new exclusive IPv4 TCP listener to `127.0.0.1` on an operating
system-assigned port, retaining ownership throughout the attempt. It configures
the fresh control with that literal loopback address and exact port. Readbacks
must confirm `ConnectToChildSession=false`,
`AllowPromptingForCredentials=false`, `GatewayUsageMethod=0` and
`EnableAutoReconnect=false`. No authentication, trust, policy, service,
firewall, account or global Child Sessions setting is changed.

The listener accepts at most one connection, verifies the peer is loopback,
then shuts down and closes that accepted socket. It never calls `recv` or
`send`, parses a protocol, or returns an RDP/TLS/authentication response. Client
negotiation bytes may already exist in the kernel receive queue; this test
does not read them and does not claim that no bytes were transmitted.

After a real `FindConnectionPoint` / `Advise`, the test makes exactly one
`Connect` call. The copied event sink implements `IDispatch::Invoke`, checks
the runtime DISPIDs, argument directions/types and owner STA thread, and records
at most 64 numeric events. There is no test-origin `Invoke` call and no
synthetically delivered event. Observer callbacks do not reenter the control.

The message pump must receive actual `OnConnecting`, followed by actual
`OnDisconnected` with its native integer reason, after the owned listener has
accepted a loopback connection. Connected must equal zero before connection
and again after disconnection. Login completion, an authentication warning,
fatal error, malformed event or event overflow fails the experiment.

Only after that observed disconnection and another fresh Connected=0 check,
the test makes the actual native `RequestClose` call. Its vtable contract and
`ControlCloseStatus` alias/enum are validated first. The call must return S_OK
with `controlCloseCanProceed=0`. It is never used to force a connecting,
connected or unknown session closed.

## Acceptance and cleanup

`verified` requires the actual native event pair, their order, the observed
owned socket lifecycle, successful disconnected `RequestClose`, and every
owned cleanup gate. Connect returning S_OK alone cannot pass. No RDP login is
expected or claimed: this deliberately closes a non-protocol loopback endpoint.

Cleanup requests `Disconnect` only on this own control when needed, pumps for
a bounded interval and requires Connected=0 before OLE close. It detaches the
observer before `Unadvise`, clears the actual cookie, releases owned references,
closes the host and destroys the hidden parent/class. The listener worker must
join before its context or socket can be destroyed; the watchdog must join
before its event handle can be closed. Winsock/OLE cleanup is explicit.

If a worker fails its bounded join, or the 45-second native watchdog expires,
the process emits `native-event-delivery-termination/v1` with
`cleanup_unverified`, then terminates **only itself** without unwinding the
still-referenced stack context. This is a failure, never a substitute for
verified cleanup. It does not terminate another process or thread. If the
control cannot be confirmed disconnected, the test reports failure and leaves
the still-owned host to its disposable process exit; no RequestClose or OLE
close is forced on an unknown state.

The wrapper allows 50 seconds, then at most five seconds to stop its own test
process. It checks the stdout file size and reads at most 65,537 bytes, rejecting
records above 65,536 bytes or invalid UTF-8/JSON. It independently verifies
boolean scope/cleanup fields, numeric HRESULTs, event counts/sequence/kinds,
connection states and RequestClose status. It never prints raw stderr, removes
only its newly created temporary output directory, and fails on unverified
wrapper cleanup. Exit 77 denotes an unavailable environment, not success.

## Output and limits

The JSON contains fixed stage identifiers, booleans, numeric HRESULTs/events,
and counters. Paths, titles, handles, process IDs, usernames, SIDs, passwords,
port numbers and protocol bytes are not printed. The token user is inspected
only to reject LocalSystem; no account data is retained in the output.

This test can validate an actual native event-delivery failure path and a
disconnected close call. It does not validate successful RDP authentication,
credential handling, all possible event signatures in delivery, a connected
close/confirmation handshake, a child session, a visible remote frame, input
delivery, physical device isolation or a complete application. A hidden host
does not provide pixel-presentation evidence. Reading native event metadata and
receiving the two selected events are distinct results.

The host/ABI helper files are unchanged copies of independently scoped tests;
the event sink is exercised by new test glue. No complete frontend, private
connection/account lifecycle or ready-to-use product is included. Source
provenance and local QA records are maintained separately from the public test.

## Build and bounded execution

The proposed workflow builds with native MSVC separately on Windows ARM64 and
x64, with warnings treated as errors, a four-minute job limit and a one-minute
runtime step. Checkout is pinned, credentials are not persisted, permissions
are read-only, and no binary/artifact upload is configured.

```powershell
cmake -S checks/events -B build/events -A x64
cmake --build build/events --config Release --parallel 2
& .\checks\events\run.ps1 -Executable .\build\events\Release\native_event_delivery_probe.exe
```

Only the reviewed executable is passed to the wrapper, with no arguments or
credentials. On an ordinary non-hosted machine the native environment guard
refuses the experiment. Linux MinGW builds do not execute the Windows binary.

## Primary references

- [Connect is asynchronous](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscax-connect)
- [OnConnecting](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscaxevents-onconnecting)
- [OnDisconnected](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscaxevents-ondisconnected)
- [RequestClose](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclient-requestclose)
- [GatewayUsageMethod](https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclienttransportsettings-gatewayusagemethod)
- [Type descriptions and aliases](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-typeattr)
- [Referenced type information](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-itypeinfo-getreftypeinfo)
