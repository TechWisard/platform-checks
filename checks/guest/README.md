# One disposable Windows 11 evaluation guest

This directory is a standalone API test fixture. It installs one Windows 11 Enterprise LTSC 2024 Evaluation x64 guest on a disposable Ubuntu 24.04 GitHub runner, then runs the existing session contract experiment inside its actual console session. The guest supervisor, host orchestrator, workflow, media facts, and environment guard are reviewable source.

**Current status: source has been cross-compiled and locally validated; this guest configuration has not yet been booted or installed.** Python unit-test inputs are synthetic parser inputs, never Windows evidence. An actual run may fail during boot, setup, first sign-in, activation, frame delivery, direct input, or cleanup. These outcomes remain failures. This fixture does not verify physical input isolation or a complete native multiseat implementation; both result flags always remain `false`.

## Integration and invocation

The existing independent harness must remain at `checks/session/child`. Copy this directory and the supplied `.github/workflows/windows-guest.yml` into the same test repository. Apply only the narrow guard extension and copy its shared helper:

```sh
git apply checks/guest/guest-environment.patch
cp checks/guest/DisposableGuestReceipt.cs checks/session/child/DisposableGuestReceipt.cs
```

The patch preserves the existing Windows GitHub runner guard and adds a separate, explicit owned-guest receipt. It does not pretend the guest is a hosted Windows runner. The receipt checks the actual SMBIOS UUID, current non-SYSTEM identity digest, current console session, expiry, and observed Secure Boot/TPM facts. This is protection against accidental execution in the wrong environment, **not a cryptographic attestation or a security boundary against a local administrator**. The payload builder requires the harness copy of the helper to match this copy exactly.

The workflow has two explicit invocation paths. `workflow_dispatch` defaults to `validate-only`, which validates local source without acquiring or executing Windows; choosing `execute` runs one guest. Alternatively, a push to `main` that changes exactly the designated trigger path `checks/guest/run-request.json` requests execution. Publish the complete reviewed source first, then create that small request file in a separate final commit, using `run-request.example.json`'s schema and a fresh descriptive request ID. The example filename does not trigger execution. Changing any other guest source file alone does not trigger this workflow. The selected trigger uses the existing concrete evaluation scope; there is no extra approval boolean or fabricated prerequisites checkbox. Do not submit a second run request while the first is active; concurrency cancellation is disabled to preserve owned-VM cleanup.

```sh
python3 -m unittest discover -s checks/guest -p 'test_*.py' -v
cd checks/guest
dotnet build GuestSupervisor/GuestSupervisor.csproj \
  --configuration Release --output build --configfile NuGet.Config --nologo \
  -p:UseSharedCompilation=false -p:NuGetAudit=false -nodeReuse:false
cd ../..
python3 checks/guest/run_guest.py
```

Only the workflow's execute step invokes `run_guest.py --execute` under `sudo`. It preserves only the four named runner environment variables; it passes no GitHub token into the guest. There is no artifact upload, media cache, screenshot capture, remote desktop listener, VNC listener, public monitor, or forwarded port.

## Fixed media, applicable terms, and acquisition

The selected Microsoft URL is [LTSC 2024 Evaluation fwlink 2289029](https://go.microsoft.com/fwlink/?linkid=2289029). `media.json` pins its exact observed HTTPS destination and size of 5,112,850,432 bytes. Actual WIM metadata identified image index 1 as **Windows 11 Enterprise LTSC 2024 Evaluation**, `EnterpriseSEval`, `Client`, build `26100.1742`. Index 2 is the N edition and is not selected.

The exact applicable file was extracted from index 1 at:

```text
/Windows/System32/en-US/Licenses/Eval/EnterpriseSEval/license.rtf
128342 bytes
SHA256 6b5d4b32236a921bacdefe19852ec0699ca2eacd72d4e57f50a2de06ede21c8e
```

The complete April 2024 terms were read before preparing execution. Section 14.d includes restrictions for limited versions; section 14.d(ii) permits evaluation, testing and demonstration within the evaluation period and excludes live operation. Section 2 contains instance, user and virtualization restrictions. The reviewed scope is one disposable guest for synthetic, single-operator API evaluation, without production, revenue service, distribution of Windows, remote human seats, or a claim to additional Windows user rights. The full applicable terms continue to govern; this test fixture does not grant a license or determine entitlement to deploy a product.

Every execution extracts the selected WIM metadata and that exact license again from its freshly downloaded ISO and compares them to the fixed facts. A changed destination, size, edition or license stops the run before accepting setup. The full ISO is acquired only during execution. No independently published Microsoft whole-ISO digest was located for this exact LTSC image. Its computed SHA256 is reported with `microsoft_published_digest_compared=false`; an ETag or a community digest is not presented as Microsoft's SHA256. HTTPS acquisition, the exact version/size check, and exact license comparison do not equal an independent whole-image signature verification.

`sdk-source.json` pins Microsoft's Windows x64 .NET SDK **8.0.427** zip and the SHA512 from [official .NET 8 release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/8.0/releases.json). The archive must contain the 8.0.427 SDK and Windows Desktop runtime/reference pack 8.0.33. A local `global.json` disables SDK version roll-forward both for the workflow's supervisor build and the guest's offline build, even when other SDKs are installed on the runner. The guest receives the SDK on a read-only payload CD and compiles the harness with all NuGet sources cleared. It does not download dependencies inside Windows.

Microsoft's [Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) describes registration/account and evaluation requirements. This fixture submits no registration form and invents no personal information. If ordinary supported unattended installation still requires an interactive account, registration, license, or other mandatory setup step, it does not bypass that step; failure to reach the supervisor remains a setup/first-logon timeout. This minimal headless result channel cannot identify the unseen exact setup page from such a timeout alone.

## Installation and guest boundaries

The host first measures CPU, available memory, free disk, `/dev/kvm`, KVM API 12, and successful creation/closure of an owned empty KVM VM object. It requires four CPUs, at least 11 GiB available memory and 80 GiB free space before installation. These are measurements on that runner, not assumptions based on a runner label. Official Ubuntu packages provide QEMU, OVMF, swtpm, xorriso and wimlib; no PPA or trust-store modification is added.

The VM has four vCPUs, 8 GiB RAM and one owned 64 GiB sparse qcow2 disk, plus read-only installation/setup/payload CDs. It uses `q35`, SMM, Microsoft-enrolled OVMF variables, TPM 2.0 CRB backed by its own swtpm state, and **only KVM** acceleration. It is initially paused; QMP must report KVM present and enabled before the first boot. There is no TCG fallback. Ordinary e1000e user-mode NAT is available for normal Windows activation, with no `hostfwd` entry or public port.

The standard answer file selects only image index 1 and its single owned disk. It specifies locales in both `windowsPE` and `oobeSystem`, creates a unique fresh local administrator A with a random strong password, and requests one initial AutoLogon. It uses one short FirstLogonCommands entry, because these commands run before the desktop and multiple entries can execute concurrently. That entry starts the ordinary own-A supervisor and returns immediately. The supervisor verifies its actual elevated non-SYSTEM A token; it does not prompt for elevation or obtain a privileged token from another process.

The normal Windows Setup `specialize` pass also writes exactly two documented presentation policy values on this new fixture: `EnableFirstLogonAnimation=0` and `DisablePrivacyExperience=1`. They apply before A's and B's first sign-ins. The supervisor reads the exact DWORD values back and reports them. These settings concern the first-sign-in animation and privacy experience. Their presence does not identify any particular past dialog, prove that a window is visible, bypass account registration, or replace the real frame/input checks. Setup runs its own specialize commands in the documented system context; the session experiment subsequently runs as the created non-SYSTEM account A.

### Setup credentials are removed before B exists

The password-bearing answer file is confined to a small separate **SESSIONSETUP** CD in the host's private temporary directory. **SESSIONPAYLOAD** contains no answer file or password; it carries only SDK/source/binaries and nonsecret per-run configuration.

After validating its SMBIOS UUID and A identity, the supervisor disables AutoLogon and deletes the owned Winlogon password value without reading it. It proves the single SESSIONSETUP CD was readable, closes that file immediately, then sends one bounded serial phase. The host pauses only its owned VM, opens `setupcd`'s tray without forcing a drive lock, removes the medium, verifies its `answerbackend` has no `inserted` medium, deletes its setup ISO, and resumes the VM. It does not change the payload or installation CD. Any failure leads to disposal of the owned VM, including when paused.

The supervisor independently waits up to 60 seconds for the same CD drive to be not ready and its formerly readable answer file to fail with a specific missing-file/path or not-ready error on three observations. Access denied or an unknown error does not prove removal. B creation and the harness cannot begin before this observation. The host's own detached-medium proof is also mandatory for success. Passwords, answer XML, accounts, SID strings, tokens, UUIDs and binding nonces are excluded from public logs.

After interactive desktop readiness, `OwnedAnswerFiles` checks only the six fixed Unattend/Autounattend candidates in the documented Panther cache locations. It accepts absence only on native errors 2/3. For an existing file, it uses a bounded XML reader with DTDs prohibited, skips Password subtrees, and requires the exact per-run owner marker in Description. It then marks that same verified, non-reparse file handle for deletion; it does not close a verified handle and later delete a potentially replaced path. An unknown file, denied access, active writer, invalid XML or missing owner marker stops the test. A fresh absence check occurs again immediately before the harness can create B. No directory traversal, registry answer-file pointer following, arbitrary-file deletion or password-value interpretation is performed. These checks concern the known setup cache candidates, not a forensic claim that all Windows traces have been erased.

## Actual evidence required

After setup media removal, the supervisor requires its process session to be the active console, WTSActive, on the input desktop, with a shell window in the same session for ten consecutive observations. It checks actual Secure Boot with `Confirm-SecureBootUEFI` and actual ready/enabled/activated TPM 2.0 through the documented TPM interfaces. It observes normal Windows `LicenseStatus=1` within a bounded period; it never reads a product key, invokes rearm, changes an expiry, installs a key, or changes activation policy.

It then copies the offline SDK into an owned Program Files directory, verifies copied bytes, compiles the independent harness, and runs its explicit alternate-account test. The harness creates its own nonadministrator B, verifies real distinct identities and both active sessions, requires its actual frame challenge, and only then attempts the one-point move/click/eight-character direct-input experiment. Existing identity, frame, input, parent-session and cleanup gates remain in effect. A COM success, login event, paint callback, started witness, or subprocess exit is insufficient.

COM1 is a file-backed QEMU serial endpoint. The supervisor emits at most 32 short phase beacons, followed by one UTF-8 JSON result no larger than 64 KiB with a byte length, SHA256, schema and fresh per-run nonce binding. The host enforces those bounds, rejects bad digests/bindings/trailing data, and prints only selected result fields. The nonce is checked but never published. Existing 30-second heartbeats may include numeric QMP storage counters. They show I/O progress, not installation success. Tool and QEMU failures print exit codes and fixed diagnostic categories, never raw stderr, command lines or paths.

Success requires every actual guest prerequisite, the independent harness's different-account/frame/direct-input checks, the full harness cleanup flags, setup-medium removal, and verified host cleanup. `physical_input_isolation_verified` and `native_multiseat_verified` remain false even on a passing run. A kernel driver replacement, independent physical monitor/HID routing, compatibility with real GPUs/USB controllers, unattended lifecycle correctness and production performance remain outside this test's evidence.

## Deadlines, cleanup, and concrete unknowns

The job limit is 90 minutes. The orchestrator limits its own work to 80 minutes with a two-minute cleanup reserve; guest installation/testing is bounded to 50 minutes and the observed first-logon supervisor to 20 minutes. Desktop readiness has a three-minute bound, security query 90 seconds, normal activation about three minutes, offline compilation five minutes, and the harness 225 seconds externally. Individual tool output and QMP operations are bounded. A finite initial 12-second space-key burst attempts to answer the stock boot-from-CD prompt; its timing has not yet been validated on this guest. Failure to catch it remains failure, not a bootloader alteration.

On normal failure, timeout or handled termination, the orchestrator independently closes QMP, stops only the QEMU/swtpm processes it created, closes its files, and removes only its own temporary directory after both processes stop. Tool subprocesses have a separate owned process group so timeouts include apt/dpkg children. Failed cleanup is explicit and cannot produce success. An external hard kill or lost runner can prevent in-process cleanup reporting; absence of a cleanup report is not evidence of cleanup. The provider's eventual runner disposal is separate from an observed successful cleanup.

The inner harness verifies removal of its own B account/task/session/sandbox and restoration of its changed child-session feature state. `GuestWorkDirectoriesRemoved` refers to the owned copied source/runtime directories. It does not claim that Windows user profiles or system traces were erased by account deletion. Disposal of the entire owned guest disk removes A, profiles, setup state and all guest-local residue from this fixture's subsequent use. No reusable Windows image is exported.

Remaining runtime questions are concrete: stock CD prompt timing; Windows Setup's discovery of the separate answer CD; the exact evaluation image's unattended first-sign-in behavior; actual elevated launcher behavior; activation network timing; QEMU/OVMF/TPM acceptance by Windows; COM1 operation; and the existing child-session frame/input path. No local source test answers those questions. A first real guest run is required.

The answer file has been parsed for XML well-formedness and reviewed against the component documentation. It has not been validated in Windows System Image Manager or by an actual Windows Setup run. Those are distinct from Python syntax and C# compilation.

## Primary references

- [Microsoft FirstLogonCommands: context, timing and parallel commands](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-firstlogoncommands), [CommandLine maximum 1024](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-firstlogoncommands-synchronouscommand-commandline), and [ordinary PowerShell `-Command` syntax](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).
- [AutoLogon](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-autologon), [LocalAccount](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-useraccounts-localaccounts-localaccount), and [OOBE automation](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/automate-oobe).
- [RunSynchronous](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-deployment-runsynchronous), [Path limit and environment expansion](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-deployment-runsynchronous-runsynchronouscommand-path), [EnableFirstLogonAnimation](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#enablefirstlogonanimation), and [DisablePrivacyExperience](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#disableprivacyexperience).
- [Confirm-SecureBootUEFI](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi), [Get-Tpm](https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm), [Win32_Tpm](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-tpm), and [SoftwareLicensingProduct LicenseStatus](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct).
- [QEMU invocation](https://www.qemu.org/docs/master/system/qemu-manpage.html), [TPM emulation](https://www.qemu.org/docs/master/specs/tpm.html), [QMP commands](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html), and [actual QEMU 8.2 removable-media command schema](https://github.com/qemu/qemu/blob/v8.2.0/qapi/block.json).
- [Ubuntu OVMF/Secure Boot example](https://documentation.ubuntu.com/core/how-to-guides/manage-ubuntu-core/test-on-qemu/), [swtpm setup](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm_setup.pod), and [wimlib extraction](https://wimlib.net/man1/wimextract.html).
- [GetSystemFirmwareTable](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable), [GetUserObjectInformation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getuserobjectinformationw), and [DriveInfo.IsReady](https://learn.microsoft.com/en-us/dotnet/api/system.io.driveinfo.isready).
- [Windows Setup answer-file search/cache and sensitive data](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview), [answer-file security practices](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/best-practices-for-authoring-answer-files), [FILE_DISPOSITION_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info), and [SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle).
