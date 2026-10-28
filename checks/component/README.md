# Disconnected component contract observation

This is a standalone Windows API probe, not a usable remote-desktop application.
It creates one fresh, unhosted `MsRdpClient10NotSafeForScripting` COM object in
a strict STA. It does not create an OLE container/window or repeat in-place
activation tests. No account, child session, credential prompt or connection is
created. No credential value is read or supplied.

## Actual coverage

The installed System32 `mstscax.dll` type library is opened with `REGKIND_NONE`.
Only the following fixed contracts are checked:

- Extended Property put/get: BSTR and VARIANT pointer shapes, directions,
  HRESULT, calling convention, native vtable bounds, unique members and QI.
- ClearTextPassword/ResetPassword: metadata and QI only. Neither method is called,
  even with an empty password.
- AllowPromptingForCredentials put/get: metadata, QI and actual native setter /
  getter calls setting false on this own disconnected object.
- RequestClose: dual interface resolution, native metadata and exact
  ControlCloseStatus enum values. RequestClose is not called.
- Ten event signatures, including the out `VARIANT_BOOL*` OnConfirmClose and both
  authentication-warning events. FindConnectionPoint/GetConnectionInterface is
  checked. No Advise, event sink, simulated event or event delivery is involved.

Configuration writes/readbacks cover fixed localhost, dimensions, ColorDepth,
CredSSP, AuthenticationLevel=1, five disabled redirections, disabled auto-reconnect,
ConnectToChildSession=true and disabled secondary credential prompting. These
are properties of the new object; WTSEnableChildSessions is never called.
EnableFrameBufferRedirection is an explicitly optional property observation;
acceptance of its value does not prove negotiation, sharing or rendering.

Only signature-validated native interfaces are called. Connected must equal zero
before and after configuration. Close and release affect only the fresh object.
The probe destroys this disposable instance without requesting persistence;
there is no save operation, registry/policy API or connection call in its code.

`verified` requires all four native contracts/QI, ten event contracts, connection
point identity, all fourteen required property checks, Connected=0 at both
observations and successful owned COM/STA cleanup. The optional framebuffer row
has its own result and HRESULT. Errors never become zero/success placeholders.

The output contains fixed member IDs, bounded numeric type descriptors, booleans
and HRESULTs. Server-supplied text, usernames, passwords, paths, COM pointers and
free-form exception descriptions are not printed. There are at most four native
interface rows, seven native method rows, ten event rows and fifteen property rows.

## Limits and execution

An unhosted configuration failure is not by itself proof that a hosted client is
broken; the exact stage/HRESULT must be compared with the host context. Successful
metadata/configuration does not prove native event callbacks, password calls,
credential UI, connection/close handshake, user identity, frames, input or physical
device isolation. The source has no Connect/Disconnect/RequestClose call path.

Build with native Windows MSVC using this CMake directory; ARM64 and x64 need
separate builds. Local MinGW cross-compilation checks compilation/linking only.
The dedicated native-component workflow builds and executes this standalone
probe on ARM64 and x64 Windows. This revision is being submitted for its first
Windows runtime measurements; local compilation alone is not an execution result.

`run.ps1 -Executable <built-exe>` imposes a 20-second process deadline, followed
by at most five seconds to confirm termination of its own process. It caps its
stdout read at 65,537 bytes and rejects results above 65,536 bytes. It validates
the single JSON record and the required success/scope gates, never prints
raw stderr, removes its own temporary output directory and returns nonzero on
timeout, failed checks or unverified cleanup. Return 77 denotes unavailable class,
not success. Run only the reviewed executable; no arguments are passed to it.

Primary references:

- https://learn.microsoft.com/en-us/windows/win32/termserv/calling-non-scriptable-interfaces
- https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-itypeinfo-getreftypeofimpltype
- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpextendedsettings-property
- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpclient-requestclose
- https://learn.microsoft.com/en-us/windows/win32/termserv/imstscaxevents-onconfirmclose
