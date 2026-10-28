# Native input interface contracts

This isolated native program reads three documented `IMsRdpInputSink` method
contracts from the installed Microsoft type library and queries that interface
on a fresh disconnected system ActiveX control. It does not invoke any input,
connection, password or session-management method. It creates no accounts and
does not change input devices, sessions, desktop selection or system policy.

The probe validates the actual method calling convention, parameter directions,
widths, vtable bounds and distinct slots. It records the exact public enum names,
direct enum or single alias shape, target names and strictly typed 32-bit
constants. It deliberately does not select constants by substring or treat
metadata as proof that input reaches a remote application. `Connected` must be
zero before and after QueryInterface. Owned references and the system control
are closed before OLE uninitialization; the wrapper enforces a 20-second process
budget and removes only its own temporary files.

Version 2 separates type-library discovery from QueryInterface. The original
probe encountered `TYPE_E_ELEMENTNOTFOUND` for the documented interface GUID in
the default installed type library; that failure occurred before its interface
query. An absent type-library entry must not be described as an absent COM
interface. The default strict contract still fails if its metadata is missing.

The additional read-only observations are:

- Independent `IMsRdpInputSink` QueryInterface on the same disconnected control.
- Independent QueryInterface for the distinct Windows SDK
  `IRDPViewerInputSink` interface. Its IID is taken from `rdpencomapi.h`, and
  none of its methods are called. This is an availability observation, not an
  assumption that the two interfaces share a vtable.
- The exact control class and containing library obtained through
  `IProvideClassInfo`, plus the default library's GUID/version/platform.
- A fixed whitelist of nine relevant type names. At most 4,096 type entries are
  visited; unrelated names and method data are not emitted.
- Existing integer `TYPELIB` resource IDs from the system DLL, limited to eight
  IDs and eight named entries. Only returned integer IDs are loaded, using the
  documented `DLL\\integer` syntax and `REGKIND_NONE`. Names are counted but not
  loaded. The DLL is mapped only as data/image resources; no DllMain is called
  by that mapping. Each resource independently records interface lookup and
  strict contract results. No resource result silently substitutes for the
  default contract.

Output is bounded to 128 KiB by the process wrapper. A failed strict contract
remains failed even when the extra observations succeed. No native input slots
are guessed or invoked. The result may be used to implement an independently
validated binding. It contains no application, UI host, remote credentials,
input router or physical device driver. The Windows x64 job is Windows Server
2025; the ARM64 job is Windows 11. Neither establishes Windows 11 Pro x64
acceptance.

Primary contracts:

- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpinputsink
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/mt786990(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/mt786991(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/mt786992(v=vs.85)
- https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-typeattr
- https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-loadtypelib
- https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-enumresourcenamesw
- https://learn.microsoft.com/en-us/windows/win32/api/rdpencomapi/nn-rdpencomapi-irdpviewerinputsink
- https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/rdpencomapi.h
