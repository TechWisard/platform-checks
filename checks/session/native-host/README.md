# Opt-in native OLE host acceptance component

This is an independent test adapter. It lets the existing child-session
experiment replace its WinForms ActiveX container with the unchanged generic
native container already tested in `checks/events`. It also subscribes the
unchanged native `EventSink` alongside the existing managed diagnostic sink.

The ordinary managed mode remains the default. Select `-NativeOleHost` on the
child or prepared PowerShell wrapper; it requires `-TestWindowInput` on the child
wrapper. The prepared wrapper already selects the full window-input experiment.

## Runtime boundary

`NativeHostBridge.dll` exports only creation, host resize/focus/translation,
numeric observations, cleanup authorization, disconnected close, and a
failure-only detach operation. It has no connection or password method, child
session API, account manager, credential prompt, production viewer, or
application command interface.

The existing managed fixture keeps account and session ownership, configuration,
connection, the child witness, screen capture, and input receipts. Its message
loop remains `Application.Run`. The native host receives a child container HWND
owned by that same process and UI thread. This is component execution in a
managed fixture, not execution of a complete native viewer or native binding.

The DLL references these public test sources without modifying them:

- `checks/events/ole_host.cpp` and `ole_host.hpp`;
- `checks/events/com_raii.hpp`;
- `checks/events/event_sink.hpp`, `abi_contract.hpp`, and `probe_support.hpp`.

## Added acceptance gates

All existing distinct-account, SID/session, witness-token, captured-frame,
geometry, focus, child-input, quiet-interval, and cleanup gates still apply.
The optional mode additionally requires:

1. The actual native OLE site, in-place activation, UI activation, child-window
   ancestry, and owner STA to be observed.
2. Real native `OnConnecting`, `OnConnected`, and `OnLoginComplete` callbacks,
   in that order, with no earlier disconnect, contract failure, or overflow.
3. Exactly one successful call to native host focus. Native container key-down
   and key-up translation counts must match the actual UI-thread message filter
   deltas from the immutable pre-emission baseline, returned only after the full
   child-input checks, exact combined-thread deltas, input release, worker Stop,
   and the final queue recheck succeed. The independent worker hook never calls
   the native translator. Its absolute counts are never substituted for UI deltas.
   Zero UI-thread key counts require zero native key translations and do not
   establish coverage of that translation path.
4. No failed or suppressed native translation. The existing parent message
   observer counts each queued message before native translation can consume it.
   Child text and mouse/button observations still come from the independent
   witness; native HRESULTs alone never prove delivery.
5. Verified disconnect and teardown: native sink detach, successful Unadvise,
   successful host close, destruction of the control HWND, release of native
   owned references and the unique managed RCW, and a balanced native OLE init.

The existing `WindowMessageObservation` is the only input filter involved in
this mode. It invokes native translation after its original observation logic.
The separate same-process worker-thread hook remains unchanged. Its removed
queue messages and the UI-filter messages must still have combined deltas of
exactly eight key-down, eight key-up and one left-button down/up pair from the
unchanged stable baseline. The baseline and final absolute observations remain
visible. No counters are reset and no additional traffic allowance is added.
Native translation counters must equal the observed UI deltas without an offset;
pre-baseline UI translations therefore cause the native component gate to fail.
All child receipts,
frame/account checks and verified hook/input cleanup remain mandatory.
Window callbacks never throw into the outer message pump: their first error is
latched and raised from the awaited experiment's `Check`, allowing the existing
receipt-based input cleanup to run. Cleanup target checks remain usable after a
translation failure.

`native_host_component_verified` and `native_host_cleanup_verified` are separate
Boolean fields. Both are mandatory for optional-mode runner success. The fields
`full_native_viewer_executed`, `full_native_binding_executed`,
`physical_input_isolation_verified`, and `native_multiseat_verified` remain false.

## COM and window lifetime

Every bridge entry validates the native owner thread. The bridge initializes
OLE on that STA, owns its host and connection point, and transfers exactly one
AddRef-held `IUnknown` to the adapter. The adapter creates a unique RCW, then
releases the transfer reference. This RCW is private to the fixture and is not
shared with another host.

At the start of normal cleanup, the native observer permits `OnConfirmClose`.
The existing fixture then removes only its owned witness and child session and
disconnects the control. It disposes password, managed-event, and extended
interface owners before the adapter releases its unique RCW. Native close
independently reads the control's current `Connected` property and refuses to
close unless it is zero. The sink is detached before Unadvise or host release.

If shutdown leaves the native handle unconsumed, the adapter retains that
context and any remaining RCW until this disposable process exits. The native
callback observer is detached without entering COM. Once a disconnected close
consumes the handle, its native owners are released even if an individual
cleanup operation fails; the per-operation result still makes the test fail.
Neither path forces Close/Release on a still-connected control or substitutes
finalizer behavior for successful teardown. Managed and native reentrancy
guards reject a close while another external call remains active.

## Building and selecting the test

`build.ps1` reads the built harness apphost's PE machine and builds a matching
x64 or ARM64 DLL with the installed CMake/MSVC toolchain. It copies only the test
DLL beside that test executable. It does not fetch or build another repository.

After the managed frame/input baseline passes on the intended runner, select
the optional mode on the same prepared invocation:

```powershell
& .\checks\session\first-logon\run-prepared.ps1 `
  -PreparationProgram .\build\first-logon\Release\first_logon_prepare.exe `
  -CalibrationProgram .\build\Release\win32_window_calibration.exe `
  -ChildSearchPreparationProgram .\build\child-search\Release\child_search_prepare.exe `
  -ResultsDirectory "$env:RUNNER_TEMP\native-host-component-$env:GITHUB_RUN_ID" `
  -AllowDisposablePrivacyPreparation -NativeOleHost -TimeoutSeconds 120
```

This selection does not remove the wrapper's existing disposable-machine,
owned-account, foreground, calibration, preparation, or restoration checks.

Compilation, JSON-validator tests, and source equality do not establish a
Windows runtime pass. New runtime evidence must identify the exact executed
commit, architecture, component events and input results, and cleanup result.
Dynamic DPI changes, stress behavior, the production top-level window and
state machine, credential UI, native configuration/password paths, and physical
device isolation are outside this component's acceptance claim.
The host translation entry point is measured. A returned `S_FALSE` does not
distinguish an unhandled accelerator from the host having no active object; no
additional branch coverage is inferred from that result.

## Primary API references

- [Unique COM RCW ownership](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getuniqueobjectforiunknown)
- [WinForms message filters](https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.imessagefilter)
- [IOleInPlaceActiveObject::TranslateAccelerator](https://learn.microsoft.com/en-us/windows/win32/api/oleidl/nf-oleidl-ioleinplaceactiveobject-translateaccelerator)
- [OLE initialization](https://learn.microsoft.com/en-us/windows/win32/api/ole2/nf-ole2-oleinitialize)
- [RDP connection events](https://learn.microsoft.com/en-us/windows/win32/termserv/imstscaxevents)
