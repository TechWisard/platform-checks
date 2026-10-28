# Native OLE hosting observation

This isolated C++ executable exercises a small OLE container against the actual
installed `MsRdpClient10NotSafeForScripting` control. It does not call `Connect`,
set a server or credentials, display credential UI, create accounts or sessions,
change RDP/service/security settings, inject input, or install a driver. No
remote desktop protocol binding or complete application is included.

## What exit 0 means

The process observed all of the following on this Windows execution:

1. A nonzero process session and its actual input desktop; an OLE STA apartment,
   confirmed with `CoGetApartmentType`; per-monitor V2 DPI awareness.
2. One owned top-level native window and the real system control activated
   in-place through the generic OLE container. `GetUserClassID` matches the
   requested CLSID; canonical `IUnknown` identity is consistent.
3. The control's actual `GetClientSite` returns the expected native parent,
   frame and client rectangles. Real in-place activation callbacks occurred.
4. `IOleInPlaceObject::GetWindow` identifies a child of the owned parent, in
   this process, UI thread and session. The native window has the visible style.
5. Its measured rectangle, translated to parent client coordinates, matches
   the initial position and then a distinct resized position. Each position
   requires at least three consecutive timer observations. The message pump
   must deliver at least ten 100 ms timer observations.
6. The timer is removed; OLE deactivation/close and site detach succeed; all
   references owned by the probe are released; the observed control HWND no
   longer exists before the parent is destroyed; the owned parent and registered
   window class are removed; and OLE is uninitialized.

`owned_com_references_released` records release of references held by this code.
It does not claim a general DLL unload or third-party memory-leak measurement.
`control_visible` and `parent_visible` are `IsWindowVisible` observations, not
evidence that pixels reached the screen or that another window did not cover
them. The result always reports `screen_presentation_verified`,
`remote_frame_verified`, `input_channel_verified`, `session_creation_verified`
and `physical_multiseat_verified` as false.

The probe emits one bounded JSON object containing numeric results, booleans,
fixed stage names and source-defined failure labels. It does not output HWNDs,
process names, identities, server text, screenshots, or pixel buffers.

## Failure and bounds

- Exit **0**: native hosting, geometry and owned cleanup verified.
- Exit **1**: API/invariant/geometry or cleanup failure. A partially successful
  observation never becomes a pass.
- Exit **77**: session zero, a non-input desktop, or missing required system
  class/module. This is an unavailable result, not a functional pass.
- Wrapper exit **124**: external timeout; cleanup is explicitly unverified.

The message pump has a 10-second observation budget and normally finishes in
about one second. Synchronous system COM calls can block outside that timer;
`run.ps1` supplies a separate 45-second bound and stops only its own child
process tree. Forced termination cannot establish native cleanup. The workflow
has an independent one-minute execution step and five-minute job bound.

The parent is shown without a foreground/topmost request. Only the probe's own
window is destroyed. Desktop handles obtained with `GetThreadDesktop` are
borrowed and are not closed. There is no foreign-window enumeration or action.

## Proposed integration

Copy only these source files into `checks/ole/`:

- `CMakeLists.txt`
- `com_raii.hpp`
- `ole_host.hpp`
- `ole_host.cpp`
- `probe.cpp`
- `run.ps1`
- `README.md`

Review `workflow-proposal.yml` as `.github/workflows/native-ole.yml`. It proposes
separate `windows-11-arm`/ARM64 and `windows-2025`/x64 jobs, a pinned checkout,
read-only repository permission and no artifact upload. These environments
exercise the native host on their actual OS; Server results do not substitute
for Windows 11 x64 results. No workflow has been applied or published by this
draft. A local cross-compiled executable is a build artifact, not runtime proof.

Build on Windows:

```powershell
cmake -S checks/ole -B build/ole -A ARM64 # or x64 on the corresponding runner
cmake --build build/ole --config Release --parallel 2
& .\checks\ole\run.ps1 -Program .\build\ole\Release\native_ole_host_probe.exe
exit $LASTEXITCODE
```

## Primary API contracts

- [System control class and CLSID](https://learn.microsoft.com/en-us/windows/win32/termserv/msrdpclient10notsafeforscripting)
- [OLE apartment initialization](https://learn.microsoft.com/en-us/windows/win32/api/ole2/nf-ole2-oleinitialize)
- [Apartment type](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cogetapartmenttype)
- [Actual client site](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-ioleobject-getclientsite)
- [In-place window context](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-ioleinplacesite-getwindowcontext)
- [Client-pixel object rectangles](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-ioleinplaceobject-setobjectrects)
- [Input desktop observation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getuserobjectinformationw)
- [Window visibility limitations](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-iswindowvisible)
# Native execution request

The first hosted run checks this source revision on native ARM64 and x64.
Runtime evidence is pending until the actual per-platform report is available.

