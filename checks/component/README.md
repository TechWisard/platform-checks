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
and HRESULTs. The additional close-enum diagnostic can print type/constant
identifiers from the fixed System32 type library, only when each entire identifier
has 1–128 ASCII letters, digits or underscores. Rejected identifiers become an
empty string with `identifier_accepted=false`; no raw fallback is printed.
Server-supplied text, usernames, passwords, paths, COM pointers and free-form
exception descriptions are not printed. There are at most four native interface
rows, seven native method rows, ten event rows and fifteen property rows.

### Close-enum diagnostic

The first Windows run rejected the RequestClose enum contract on both tested
architectures while the other three native contracts, ten event signatures and
all fifteen property readbacks passed. The initial record establishes the
parameter shape (`VT_PTR` to `VT_USERDEFINED`, flags `FOUT | FRETVAL`), but does
not identify which referenced enum condition failed. This diagnostic records
that already-referenced type before invoking the strict validator:

- Actual type kind/name, variable count, flags, instance size and alias shape
  (if the immediate type is an alias); no recursive type-library inventory.
- At most sixteen variable descriptors, including actual variable kind,
  declared type, constant VARIANT type and integer value when present. Values
  are decimal strings with a separate signedness field, preserving exact 64-bit
  integers without JSON consumer rounding. Other VARIANT payloads are not read.
- Exact name-match bits: 1 for `controlCloseCanProceed`, 2 for
  `controlCloseWaitForEvents`. `strict_constant_bits` also require the original
  `VT_I4` representation and values 0/1. The type name has its separate exact
  `ControlCloseStatus` match flag. These diagnostic bits do not replace the
  strict validator or enter any PASS decision.

Run 40701169355 at commit `0222b25bcef874969097cd27efafb970a2beaa3c`
measured the same immediate type on both architectures: exact public name
`ControlCloseStatus`, `TKIND_ALIAS`, size 4, no own variables, and
`tdescAlias.vt=VT_USERDEFINED`. The previous validator rejected that alias as
though the parameter had to reference an enum directly. The alias target was
not read in that run; its enum kind and constants remain unverified.

The strict validator now accepts the measured public-name/size/alias shape and
resolves exactly one reference. That target must itself be `TKIND_ENUM`, size
4, with exactly two `VAR_CONST` values represented as `VT_I4`: the original
exact names and values 0/1 are still required. A further alias, wrong type,
wrong name/value, numeric conversion or unavailable descriptor is not accepted.
The existing direct enum path also retains the exact public-name requirement.

The diagnostic follows that same named four-byte alias shape at most once and
records `close_enum_alias_target_diagnostic` with the same identifier filter and
constant bounds. Because the alias has no own variables, at most sixteen
constant rows are read across both type records. Diagnostic fields never
replace validator results or enter a PASS decision. Diagnostic failure or
truncation is explicit and does not overwrite the original contract failure.
Native calls, required success gates, connection state requirements and the
wrapper deadline remain unchanged. RequestClose remains metadata-only and is
never called.

## Limits and execution

An unhosted configuration failure is not by itself proof that a hosted client is
broken; the exact stage/HRESULT must be compared with the host context. Successful
metadata/configuration does not prove native event callbacks, password calls,
credential UI, connection/close handshake, user identity, frames, input or physical
device isolation. The source has no Connect/Disconnect/RequestClose call path.

Build with native Windows MSVC using this CMake directory; ARM64 and x64 need
separate builds. Local MinGW cross-compilation checks compilation/linking only.
The dedicated native-component workflow builds and executes this standalone
probe on ARM64 and x64 Windows. Run 40699247035 at commit
`902aa5ec8aaed54a9a7ba108394fcaa2d4482bcf` failed the close-enum contract on
Windows 11 ARM64 and Windows Server 2025 x64; both reported successful owned
cleanup and Connected=0 before/after configuration. The next diagnostic run
identified the immediate alias on both systems and preserved the strict FAIL.
This one-level alias-resolution revision has not yet run on Windows; local
cross-compilation alone is not an execution result.

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
- https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-typeattr
- https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-vardesc
- https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-itypeinfo-getvardesc
- https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nf-oaidl-itypeinfo-getreftypeinfo
