# Early bootstrap observations

The latest evaluation guest timed out without the original COM1 `HELLO`.
That observation cannot distinguish Windows setup/OOBE, the first-logon
PowerShell command, CLR loading, the COM1 constructor, or payload/configuration
validation. No RDP connection result was produced in that run.

An independent COM2 UART backed by a fixed 4 KiB QEMU ring carries only numeric
diagnostics. It has no network endpoint. A best-effort specialize command writes
one marker; the existing first-logon command writes a few more around its
unchanged media discovery, ownership-tag check and `Start-Process`. The command
still inherits the fresh administrator's token, does not wait for the child,
and does not change execution policy.

The supervisor then records entry, argument checks, COM1 construction, payload
and configuration checks. Before `HELLO`, handled/unhandled exceptions emit
only their numeric HRESULT and, when directly available, a Win32 error code.
It does not emit exception types/messages, account names, paths, nonce values,
credentials, registry data or event text.

| Stage ID | Observation | Code |
|---|---|---|
| 0 | Specialize marker command reached | 0 |
| 1 | First-logon PowerShell body entered | 0 |
| 2 | Matching payload CD candidates | Count, 0–26 |
| 3 | Ownership tag exists | 0 or 1 |
| 4 | About to call `Start-Process` | 0 |
| 5 | PowerShell bootstrap exception | Signed HRESULT |
| 10 | Managed supervisor `Main` entered | 0 |
| 11 | Supervisor arguments checked | 0 accepted, 64 rejected |
| 12 | Existing COM1 channel constructed | 0 |
| 13 | Payload drive type/label accepted | 0 |
| 14 | Configuration file length accepted | 0 |
| 15 | Configuration JSON parsed | 0 |
| 16 | Configuration nonce shape accepted | 0 |
| 17 | Supervisor exception before `HELLO` | Signed HRESULT |
| 18 | Direct Win32 exception's native error | Signed integer |

The host performs exactly one terminal `ringbuf-read` (base64, maximum 4096
decoded bytes), after the experiment outcome is known and before stopping QEMU.
There is no extra diagnostic QMP read in the live test path. The parser accepts
at most 16 records, rejects unknown/overlong lines to a bounded counter, and
never emits raw text. All diagnostic read/summary/logging code is best-effort
and cannot prevent the existing host cleanup. A capture failure records fixed
numeric error 1. Ring overflow drops old data without a new acceptance failure
or growing disk file; loss itself is not observable from the terminal snapshot.

These records are `diagnostic_only`; emitter identity is not authenticated by
this protocol. They never satisfy the original nonce-bound `HELLO` or any test,
activation, child-session, input or cleanup gate. An absent marker is not proof
that its command never ran: COM2 itself may be unavailable. The 250 ms serial
write setting is not a hard deadline on every native open/configuration call.
The existing outer VM/process deadlines remain unchanged.

The failure screenshot remains private and temporary. Only its existing fixed
label IDs/counts are retained; no raw image or OCR text is added to artifacts.

The ring backend and base64 read are documented in the official
[QEMU invocation manual](https://www.qemu.org/docs/master/system/qemu-manpage.html)
and [QMP reference](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html#command-ringbuf-read).
