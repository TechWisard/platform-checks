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

The result may be used to implement an independently validated native input
binding. It does not contain an application, UI host, remote credentials, input
router or physical device driver. The Windows x64 job is Windows Server 2025;
the ARM64 job is Windows 11. Neither establishes Windows 11 Pro x64 acceptance.

Primary contracts:

- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpinputsink
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/mt786990(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/mt786991(v=vs.85)
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/mt786992(v=vs.85)
- https://learn.microsoft.com/en-us/windows/win32/api/oaidl/ns-oaidl-typeattr
