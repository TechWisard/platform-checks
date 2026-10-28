# Session API contracts

Independent Windows API experiments. No application backend, device-assignment
code, installer, or release binary is included.

`environment.cpp` is read-only. It reports the actual OS build, architecture,
process/console session IDs, window-station/desktop accessibility, child-session
query results, and installed Remote Desktop COM interfaces. Named-property reads
use Microsoft's installed type library. It never enables a feature, connects a
session, supplies credentials, changes policies, or installs a driver.

Exit 0 means the queried prerequisites were observed. Exit 77 means an unavailable
prerequisite; exit 1 means a failed program invariant. A successful preflight does
not prove session creation, independent users, independent input or physical
display ownership. Account names, SIDs, device names and credentials are not
printed. Native results from Windows 11 ARM64 do not establish x64 compatibility.

Sources:

- https://learn.microsoft.com/en-us/windows/win32/termserv/child-sessions
- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpextendedsettings
- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpextendedsettings-property
- https://learn.microsoft.com/en-us/windows/win32/termserv/imsrdpinputsink

Microsoft documents a maximum of one active connected child session per machine.
Its lifetime depends on its parent, and it has no independent lock/logon screen.
These limits must remain visible when interpreting any experiment.

`child/` contains a separate, time-limited connection/rendering contract
experiment for disposable Windows test machines. It requires an explicit flag
before changing child-session enablement, records actual session and frame
evidence, and restores the state it changed. It is not an application backend.
See its README for cleanup, identity, authentication, and functional limits.
CI publishes only text logs, with no binaries or screenshots.
