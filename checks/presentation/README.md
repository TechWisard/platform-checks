# Bounded startup presentation observation

This read-only Windows probe classifies predefined English setup labels inside
an already foreground CloudExperienceHost window on a disposable hosted runner.
It counts visible and offscreen matches separately. A generic web-app host name
alone does not identify its current page.

Before reading UI Automation it verifies the active console session, the
foreground root's session, class, package family and application identity.
It queries only that window's subtree, with one-second UI Automation provider
timeouts, at most 512 elements, one shared eight-second budget for traversal
and additional metadata, and a twenty-second process deadline. It rechecks
the foreground owner before and after additional metadata.
The wrapper terminates only the process it started if the deadline is reached.

The fixed labels include Accept, Next, Back, Yes, No, More, Continue, Done, OK,
Cancel, Learn more and Save. In `label_matches`, the existing v1 `count` and
`last_control_type` still describe visible matches; `visible_count` repeats
that count and `hidden_count` / `last_hidden_control_type` describe offscreen
matches. "Visible" here means UI Automation `IsOffscreen` is false, not a
separate pixel, occlusion or clickability proof.

Only after an exact visible "Choose privacy settings for your device" match,
a matching root HWND and an unchanged verified owner, the probe reads metadata
for at most 32 action candidates from the same snapshot. Candidates are button,
checkbox, radio button, hyperlink, combo box, list item, menu item, split button
or tab item types, plus elements with a fixed action label. They may be disabled
or offscreen. Their process, password flag, type, name classification, offscreen
and enabled state are read again before reporting. An unfamiliar custom control
without a fixed action label is not included; this is not a full UI inventory.

Each candidate reports its numeric control type, `IsOffscreen`, `IsEnabled`,
fixed label category, and an AutomationId only if the entire ID is 1–128 ASCII
characters from `[A-Za-z0-9_.:-]`. Empty, excessive-length or disallowed IDs
are reported as null with a fixed status; no truncation or raw fallback is used.
The original BSTR buffers are erased and released. Invoke, Toggle and ScrollItem
availability are read as UIA boolean properties; false includes UIA's documented
default when a pattern is unsupported. Errors are null, with a numeric HRESULT.
For a supported Toggle pattern, only the read-only `CurrentToggleState` getter
is used: 0 means Off, 1 On, 2 Indeterminate; unread or failed state is null.

Unknown names, text, titles, account names, passwords, value/text-pattern
contents, paths, native handles and screenshots are not emitted. Password
elements and elements attributed to another process are skipped. Foreground
owner changes discard all label and action details. UI Automation observations
are sequential, not an atomic snapshot, and index/AutomationId alone is not
authorization to operate a later control.

The probe never calls Invoke, Toggle, ScrollIntoView, scrolling, focus or input
methods. It does not dismiss windows, change policies or create accounts or
sessions. UI Automation automatic focus is disabled on the client. The existing
twenty-second wrapper and its scope are unchanged.

`observed` means the read-only observation completed. It is not a session,
frame, input or multiseat acceptance result. Exact labels are case-insensitive;
missing labels do not prove that a different language or UI variant is absent.

Build this standalone CMake directory with native Windows MSVC. Local MinGW
cross-compilation checks syntax and linkage; only a Windows run checks runtime.

Primary API references:

- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nn-uiautomationclient-iuiautomation2
- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomation-elementfromhandle
- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationelement-findall
- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationelement-get_currentautomationid
- https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-control-pattern-availability-propids
- https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-propertiesforclients
- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationelement-getcurrentpatternas
- https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationtogglepattern-get_currenttogglestate
- https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getpackagefamilyname
- https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getapplicationusermodelid
