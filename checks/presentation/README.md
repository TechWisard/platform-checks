# Bounded startup presentation observation

This read-only Windows probe checks one question: which predefined English
setup labels are visible inside an already foreground CloudExperienceHost
window on a disposable hosted runner? A generic web-app host name alone does
not identify its current page.

Before reading UI Automation it verifies the active console session, the
foreground root's session, class, package family and application identity.
It queries only that window's subtree, with one-second UI Automation provider
timeouts, at most 512 elements, an eight-second traversal budget and a
twenty-second process deadline. It rechecks the foreground owner afterwards.
The wrapper terminates only the process it started if the deadline is reached.

The report contains counts and fixed label IDs. Unknown text, titles, account
names, passwords, element values, paths, native handles and screenshots are
not emitted. Password elements, offscreen elements and elements attributed to
another process are skipped. The probe does not request patterns, invoke
controls, set focus, send input, dismiss windows, change policies or create
accounts or sessions. UI Automation automatic focus is disabled on the client.

`observed` means the read-only observation completed. It is not a session,
frame, input or multiseat acceptance result. Exact labels are case-insensitive;
missing labels do not prove that a different language or UI variant is absent.

Build this standalone CMake directory with native Windows MSVC. Local MinGW
cross-compilation checks syntax and linkage; only a Windows run checks runtime.

Primary API references:

- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nn-uiautomationclient-iuiautomation2
- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomation-elementfromhandle
- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationelement-findall
- https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagefamilyname
- https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getapplicationusermodelid
