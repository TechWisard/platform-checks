# Anonymous section protection and view lifetime

This independent Windows user-mode diagnostic creates only its own anonymous
4 KiB sections. It calls the Windows native section API from ntdll, maps an
initially read-only consumer, and records whether `VirtualProtect` can change
that view to shared read/write access. It compares a read/write section using
the original handle, a read/write section with a read-only duplicate handle,
and a read-only section. Output is structured JSON with actual OS build,
return status and each cleanup result.

For the writable sections, the probe observes producer writes and clears.
For all three, it closes all section handles and unmaps the producer while
checking that the remaining consumer view is still valid, then unmaps it.
The probe does not require elevation.

Success means the observations and cleanup completed and the read-only section
did not admit shared read/write protection. Writable-section elevation is an
observation, not a pass criterion. This does **not** test copy-on-write changes,
driver MDLs, kernel aliases, WOW64, foreign processes, or a product runtime.
No private product source, prebuilt executable, driver, or third-party payload
is used. Windows runners compile this diagnostic from this folder's source.

Primary API references:

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
- https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-memory-sections
- https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
