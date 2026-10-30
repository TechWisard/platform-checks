# Temporary root-device property observation

This independent native check measures `SetupDiSetDeviceRegistryPropertyW` for
`SPDRP_SERVICE` on a newly registered root-enumerated LegacyDriver devnode. Both
the class and the property setter are reserved according to Microsoft; an
observed successful call is **not a supported cross-version API guarantee**.

The program requires `--disposable-root-probe` and an elevated process. Run it
only on a disposable Windows test machine. It generates a unique full device
instance ID and a unique service name. It verifies that neither already exists,
creates only that device, performs `DIF_REGISTERDEVICE`, sets CONFIGFLAGS to zero,
records the service setter result plus exact readback, and attempts the matching
property clear. Finally it removes its own devnode through `DIF_REMOVE` and checks
absence using a fresh device information set, including non-present instances.

The test **does not create a service, add a driver package, request a kernel
driver load, modify class filters, patch the operating system, or carry private
product code**. No existing device or service is selected by name or class scan.
The generated service name is a deliberately absent target. Consequently this
observation cannot establish real driver binding, AddDevice, PnP start,
interface publication, or physical input delivery.

## Build and run

```powershell
cmake -S checks/root-device -B build/root-device -A x64
cmake --build build/root-device --config Release
.\checks\root-device\run.ps1 -Executable .\build\root-device\Release\root_device_property.exe
```

Exit 0 from the native binary means the setter was actually measured, its result
agrees with readback, and cleanup was verified. It does **not** mean the setter
was accepted. Exit 77 means an earlier prerequisite prevented the measurement
and the process cleaned up everything it owned. Exit 1 means an invariant or
cleanup failed. The wrapper reports unavailable runs explicitly; the JSON field
`native_observation_completed` distinguishes them from measured runs.

The workflow runs on disposable hosted x64 Windows Server 2022 and 2025 runners.
It does not establish Windows 11 client compatibility. A process forced down by
an external job cancellation cannot attest cleanup; no successful result should
be inferred from a cancelled or missing report.

## API sources

- [SetupDiCreateDeviceInfoW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdicreatedeviceinfow)
- [DIF_REGISTERDEVICE](https://learn.microsoft.com/en-us/previous-versions/windows/drivers/install/dif-registerdevice)
- [SetupDiSetDeviceRegistryPropertyW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdisetdeviceregistrypropertyw)
- [Reserved setup classes](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-reserved-for-system-use)
- [DIF_REMOVE](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/dif-remove)
