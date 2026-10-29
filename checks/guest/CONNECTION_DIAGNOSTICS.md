# Bounded connection observations

The child harness now takes one read-only snapshot immediately before `Connect`.
It re-queries the actual child-enable state, process/console session, parent WTS
state and whether the current input desktop name matches the thread desktop in
the current window station. It records numeric Windows build/UBR/product SKU and
the four-part file version of **the loaded** `mstscax.dll`; unavailable values
remain null, with a numeric error when the query failed. A same-named file found
on disk is not substituted for a loaded module.

Service IDs 1 and 2 are `TermService` and `UmRdpService`. Only
`SERVICE_QUERY_STATUS` is requested. State and service exit codes are observed,
without starting/stopping services, emitting process IDs or changing policies.
After an experiment fails having begun `Connect`, a second services-only
snapshot is recorded as `connection_postfailure_services`, before cleanup and
the event-log queries. This is a sample after the failed attempt/boundary, not
the service state at the COM callback. Individual query failures remain numeric;
handled observation/logging exceptions cannot replace the original failure.

Registry IDs preserve this fixed order:

| ID | Value |
|---|---|
| 1 | machine `fDenyTSConnections` |
| 2 | policy `fDenyTSConnections` |
| 3 | listener `fEnableWinStation` |
| 4 | listener `PortNumber` |
| 5 | listener `SecurityLayer` |
| 6 | listener `UserAuthentication` |
| 7 | listener `fPromptForPassword` |
| 8 | policy `SecurityLayer` |
| 9 | policy `UserAuthentication` |
| 10 | policy `fPromptForPassword` |
| 11 | credential policy `AllowDefaultCredentials` |
| 12 | credential policy `AllowDefaultCredentialsWhenNTLMOnly` |
| 13 | credential policy `DenyDefaultCredentials` |

Registry availability is 0 observed DWORD, 1 absent, 2 query failure, 3 unexpected
type. Values never collapse unavailable/absent to zero. A Win32 exception's
native error is preserved; other errors use their signed HRESULT or existing
contract code. These are observations, not permission to change settings.

If the experiment fails after beginning `Connect`, it queries only that observed
time window (at most five minutes), newest records first. Channel IDs are:

1. TerminalServices-RDPClient/Operational.
2. RemoteDesktopServices-RdpCoreTS/Operational.
3. TerminalServices-LocalSessionManager/Operational.
4. TerminalServices-RemoteConnectionManager/Operational.
5. Security, restricted to event 4625.

Each channel contains at most eight records; a ninth is used only to mark the
limit. The iteration budget is three seconds, and each event read requests a
100 ms timeout. This is not a hard three-second bound on every native call;
the existing external harness/process deadline still applies. Channels remain
disabled if they were disabled. Channel availability is 0 queried, 1 disabled,
2 query failure, 3 iteration budget expired. Event fields contain only numeric
ID/version/level, UTC, and a closed set of numeric status/reason fields. XML is
limited to 64 KiB with DTD/external resolution disabled. No event message, XML,
account name, SID, machine name, address, credential or path is emitted.
Records are attributed to the time window only; an unrelated concurrent event
cannot be labelled as the cause of this connection's failure.

Guest10 retained eight informational records from channel 4 and hit its limit.
After all five original channel reads, an optional `earlier_warning_error`
selection uses only the remaining part of that same three-second budget. It
applies only when channel 4 was available, capped, and its eight retained records
all have level 4 and valid UTC timestamps inside the original query window.
It reads channel 4 once more, restricted to levels 1/2/3 and timestamps from the
same original start through the oldest retained timestamp, inclusive. At most
eight additional numeric records are retained; a ninth marks the separate
limit. No query interval is widened and Security's original read keeps its
position and budget priority. Availability is 0 queried, 2 numeric query error,
or 3 insufficient remaining iteration budget; `through_utc` identifies the
cutoff. Native event API calls still have the external deadline limitation above.

The original five channel payloads are preserved if the optional read fails.
The supervisor independently rejects malformed optional data, emits only the
fixed `earlier_warning_error_rejected=true` marker, and preserves the valid
original channels. Optional records require level 1/2/3, a UTC timestamp no
later than the validated cutoff, and the same closed numeric code allowlist.

The guest supervisor preserves this data under `test.connection`, independently
of its existing failure projection and all success/cleanup gates. It also keeps
the ordered connection lifecycle, including legitimate null-code RDP events,
the authentication before/after values and original session/enable flags. All
names and value shapes are explicitly checked. There is at most one pre-connect
snapshot, one post-failure services snapshot and one event-log observation,
at most 32 selected lifecycle records, and a
24 KiB encoded-event budget. Malformed records are counted and omitted; overflow
sets `events_truncated`. The original numeric failure is retained separately.
Queued RDP timestamps are **drain times**, not callback or network timings.

This increment corrects the loss of already-available connection observations.
It does not assert that a diagnostic is a successful connection or that basic
disconnect 4 has the meaning of extended disconnect 4. The last guest run
observed **basic 4 / extended 0**; its underlying cause remains unproven.

Primary API references: [Child Sessions](https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions),
[basic disconnect](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscaxevents-ondisconnected),
[extended disconnect](https://learn.microsoft.com/en-us/windows/win32/termserv/extendeddisconnectreasoncode),
[service status](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex),
[product SKU](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo).
