# Independent Windows API checks

Each source has its own `main` and can be built and run separately. These are
read-only compatibility probes and bounded conversion tests. They do not form an
application, driver, installer, or service.

| Source | Coverage |
| --- | --- |
| `utf16.cpp` | Strict UTF-16 to UTF-8 conversion, size and termination checks, invalid surrogate rejection, 1,000 deterministic Unicode round trips |
| `display_config.cpp` | Active DisplayConfig buffer negotiation, bounded retry, mode indices and target identity uniqueness |
| `raw_input.cpp` | Raw Input enumeration, buffer negotiation, keyboard/mouse metadata and identity consistency |
| `audio_endpoints.cpp` | MMDevice COM object lifetime, active endpoint enumeration, identity/state/data-flow consistency |
| `device_info.cpp` | SetupAPI enumeration of present device nodes, bounded instance IDs and string properties |
| `sessions.cpp` | WTS enumeration, distinct session IDs, valid states, presence of the current process session |

The five API probes run three warm-up queries and 24 repeated queries. They fail
if the final process handle count exceeds the warmed count by more than 16. This
detects substantial linear handle leakage; it is not a complete memory-leak test.
Output contains only counts, numeric error codes, and static diagnostic text.
Native identifiers are checked in memory but not printed or saved. Account names,
network addresses, device descriptions, and device identities are not reported.

Exit `0` means the performed assertions passed. Exit `1` means failure. Display
configuration exits `77` when Windows reports no WDDM support or no access to the
console desktop. CTest must classify exit `77` as skipped, rather than passed.
An empty Raw Input list or audio endpoint list is a valid API response and is
reported as a count of zero; per-device assertions then have no hardware coverage.
No other API failure is silently converted to a pass or skip.

These checks establish only the API behavior and helper logic that they execute.
They do not test physical rendering, keyboard input delivery, audio playback,
hot-plug timing, driver installation, or integration with any application.

Microsoft references:

- [DisplayConfig buffer negotiation and supported-session errors](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdisplayconfigbuffersizes)
- [QueryDisplayConfig](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-querydisplayconfig)
- [GetRawInputDeviceList](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getrawinputdevicelist)
- [EnumAudioEndpoints](https://learn.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-immdeviceenumerator-enumaudioendpoints)
- [SetupDiGetDeviceInstanceIdW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinstanceidw)
- [WTSEnumerateSessionsW](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsw)
