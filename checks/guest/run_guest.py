#!/usr/bin/env python3
"""One disposable, source-only session experiment; no reusable VM service.

The default mode validates/generates a plan only. --execute checks the fixed
official media and exact evaluation terms before setup. No success is inferred
from QEMU startup, an open serial port, installation, or an inner HRESULT.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import failure_diagnostics

HERE = Path(__file__).resolve().parent
GIB = 1024**3
ENDPOINTS = {"go.microsoft.com", "software-static.download.prss.microsoft.com", "builds.dotnet.microsoft.com"}
UNATTEND = "urn:schemas-microsoft-com:unattend"
WCM = "http://schemas.microsoft.com/WMIConfig/2002/State"
ET.register_namespace("", UNATTEND)
ET.register_namespace("wcm", WCM)


class Failure(Exception):
    def __init__(self, stage: str, code: int = 0, diagnostic: str | None = None):
        super().__init__(stage)
        self.stage, self.code = stage, code
        self.diagnostic = diagnostic


def require(condition: bool, stage: str) -> None:
    if not condition:
        raise Failure(stage)


def emit(stage: str, **details: object) -> None:
    print(json.dumps({"schema": "windows-guest-host/v1", "stage": stage, **details}, separators=(",", ":")), flush=True)


def sha(path: Path, algorithm: str = "sha256") -> str:
    value = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def diagnostic_category(data: bytes) -> str:
    # Only fixed categories leave the host. Never emit a fragment of stderr,
    # arbitrary paths, arguments, setup XML, guest serial data, or credentials.
    text = data[:16384].decode("utf-8", errors="replace").lower()
    patterns = (
        ("disk_full", ("no space left on device",)),
        ("permission_denied", ("permission denied", "operation not permitted")),
        ("memory_allocation", ("cannot allocate memory", "could not allocate memory")),
        ("kvm_initialization", ("failed to initialize kvm", "could not access kvm", "kvm acceleration not available")),
        ("resource_busy", ("device or resource busy", "failed to get write lock")),
        ("network_resolution", ("temporary failure resolving", "could not resolve")),
        ("network_download", ("failed to fetch", "certificate verification failed")),
        ("missing_file", ("no such file or directory", "cannot find the file")),
        ("unsupported_option", ("invalid option", "not a valid device model", "property not found", "invalid parameter")),
        ("package_configuration", ("errors were encountered while processing",)),
    )
    return next((category for category, needles in patterns if any(needle in text for needle in needles)), "unclassified")


def load_media() -> tuple[dict, dict, dict]:
    document = json.loads((HERE / "media.json").read_text())
    require(document.get("schema") == "windows-evaluation-media/v1", "media_manifest_schema")
    profile = document["profiles"][document["selected_profile"]]
    sdk = json.loads((HERE / "sdk-source.json").read_text())
    require(sdk.get("version") == "8.0.427" and sdk.get("rid") == "win-x64" and
            re.fullmatch(r"[0-9a-fA-F]{128}", sdk.get("hash", "")) is not None, "sdk_manifest_invalid")
    return document, profile, sdk


def require_media_facts(document: dict, profile: dict) -> None:
    review = document["license_review"]
    require(review.get("profile") == document["selected_profile"] and
            re.fullmatch(r"[0-9a-fA-F]{64}", review.get("evaluation_terms_sha256") or "") is not None and
            isinstance(review.get("evaluation_terms_wim_path"), str) and
            review.get("scope") == "single_operator_automated_evaluation", "applicable_terms_provenance_missing")
    require(profile.get("image_index") == 1 and isinstance(profile.get("image_name"), str), "image_selection_not_verified")


def preflight(directory: Path) -> None:
    require(platform.machine() == "x86_64", "host_x64_required")
    require(os.geteuid() == 0, "host_kvm_requires_sudo")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("RUNNER_OS") == "Linux", "disposable_github_linux_host_required")
    cpu_count = len(os.sched_getaffinity(0))
    require(cpu_count >= 4, "four_host_cpus_required")
    memory = {key: int(value.split()[0]) * 1024 for key, value in
              (line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())}
    require(memory.get("MemAvailable", 0) >= 11 * GIB, "host_memory_insufficient")
    disk = shutil.disk_usage(directory)
    require(disk.free >= 80 * GIB, "host_disk_insufficient")
    require(stat.S_ISCHR(Path("/dev/kvm").stat().st_mode), "kvm_character_device_missing")
    kvm = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    try:
        require(fcntl.ioctl(kvm, 0xAE00, 0) == 12, "kvm_api_not_12")
        # Create and immediately close only our own empty VM object. This is
        # actual KVM capability evidence, not a successful Windows boot.
        empty_vm = fcntl.ioctl(kvm, 0xAE01, 0)
        require(empty_vm >= 0, "kvm_vm_creation_failed")
        os.close(empty_vm)
    finally:
        os.close(kvm)
    emit("host_preflight_verified", cpu_count=cpu_count, available_memory_bytes=memory["MemAvailable"],
         available_disk_bytes=disk.free, kvm_api=12, empty_kvm_vm_created_and_closed=True, windows_boot_verified=False)


class Deadline:
    def __init__(self) -> None:
        self.end = time.monotonic() + 80 * 60

    def seconds(self, maximum: float) -> float:
        left = self.end - time.monotonic()
        require(left > 120, "host_deadline_cleanup_reserve")
        return min(maximum, left - 120)


def stop_command_group(process: subprocess.Popen) -> bool:
    # This process was started with start_new_session=True. Never signal a
    # caller's group or locate processes by name. Apt/dpkg children are included.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            continue
        if sig == signal.SIGKILL:
            return True
        # Even if the leader exits, terminate remaining members of our group.
    return process.poll() is not None


def command(arguments: list[str], deadline: Deadline, maximum: float, output: Path | None = None,
            *, maximum_output_bytes: int = 4 * 1024 * 1024) -> bytes:
    # Commands never receive passwords as argv. All arguments are passed as
    # separate strings, without a shell or execution of downloaded scripts.
    require(maximum_output_bytes > 0, "tool_output_bound_invalid")
    end = time.monotonic() + deadline.seconds(maximum)
    target = output.open("xb") if output is not None else None
    process = None
    completed = False
    captured = bytearray()
    diagnostic = bytearray()
    counts = {"stdout": 0, "stderr": 0}
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                left = end - time.monotonic()
                require(left > 0, "tool_timeout")
                for key, _ in selector.select(min(0.25, left)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    channel = key.data
                    counts[channel] += len(block)
                    bound = maximum_output_bytes if channel == "stdout" else 4 * 1024 * 1024
                    require(counts[channel] <= bound, "tool_" + channel + "_limit")
                    if channel == "stdout":
                        if target is not None:
                            target.write(block)
                        else:
                            captured.extend(block)
                    elif len(diagnostic) < 16384:
                        diagnostic.extend(block[:16384 - len(diagnostic)])
        left = end - time.monotonic()
        require(left > 0, "tool_timeout")
        try:
            code = process.wait(timeout=left)
        except subprocess.TimeoutExpired:
            raise Failure("tool_timeout") from None
        completed = True
        if code != 0:
            raise Failure("tool_" + Path(arguments[0]).name.replace("-", "_"), code, diagnostic_category(diagnostic))
        return bytes(captured)
    finally:
        try:
            if process is not None and not completed:
                require(stop_command_group(process), "tool_cleanup_unverified")
        finally:
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            if target is not None:
                target.close()


class MicrosoftRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == "https" and parsed.hostname in ENDPOINTS and parsed.username is None, "download_redirect_rejected")
        return super().redirect_request(request, file, code, message, headers, url)


def download(url: str, destination: Path, deadline: Deadline, *, expected_length: int | None,
             expected_digest: str | None, algorithm: str, expected_url: str | None, maximum_bytes: int) -> str:
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https" and parsed.hostname in ENDPOINTS and parsed.username is None, "download_source_rejected")
    opener = urllib.request.build_opener(MicrosoftRedirects())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with opener.open(request, timeout=30) as response:
        require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity", "download_response_invalid")
        if expected_url is not None:
            require(response.url == expected_url, "download_version_redirect_changed")
        declared = int(response.headers.get("Content-Length", "-1"))
        require(0 < declared <= maximum_bytes, "download_length_unavailable_or_large")
        if expected_length is not None:
            require(declared == expected_length, "download_declared_length_changed")
        digest = hashlib.new(algorithm)
        total = 0
        start = time.monotonic()
        with destination.open("xb") as file:
            while True:
                deadline.seconds(1)
                require(time.monotonic() - start < 20 * 60, "download_phase_timeout")
                block = response.read1(1024 * 1024)
                if not block:
                    break
                total += len(block)
                require(total <= declared and total <= maximum_bytes, "download_overrun")
                digest.update(block)
                file.write(block)
        require(total == declared, "download_truncated")
    actual = digest.hexdigest()
    if expected_digest is not None:
        require(secrets.compare_digest(actual.lower(), expected_digest.lower()), "download_digest_mismatch")
    return actual


def verify_media(iso: Path, profile: dict, review: dict, work: Path, deadline: Deadline) -> None:
    wim = work / "install.wim"
    command(["7z", "x", "-so", str(iso), "sources/install.wim"], deadline, 300, wim, maximum_output_bytes=6 * GIB)
    require(0 < wim.stat().st_size <= 6 * GIB, "install_wim_size_invalid")
    metadata = command(["wimlib-imagex", "info", str(wim), "1", "--xml"], deadline, 60)
    tree = ET.fromstring(metadata)
    image = tree.find("IMAGE[@INDEX='1']")
    require(image is not None, "install_image_index_missing")
    require(image.findtext("NAME") == profile["image_name"] and
            image.findtext("WINDOWS/EDITIONID") == profile["expected_edition"] and
            image.findtext("WINDOWS/INSTALLATIONTYPE") == "Client" and
            image.findtext("WINDOWS/VERSION/BUILD") == str(profile["expected_build"]), "install_image_metadata_changed")
    terms = command(["wimlib-imagex", "extract", str(wim), "1", review["evaluation_terms_wim_path"], "--no-globs", "--to-stdout"],
                    deadline, 120, maximum_output_bytes=1024 * 1024)
    require(0 < len(terms) <= 1024 * 1024 and hashlib.sha256(terms).hexdigest().lower() ==
            review["evaluation_terms_sha256"].lower(), "applicable_evaluation_terms_changed")
    # The full exact bytes were reviewed before this execution was permitted.
    # Do not publish the license, WIM, ISO, account XML, or runtime as artifacts.
    wim.unlink()
    emit("media_and_reviewed_terms_verified", edition=profile["expected_edition"], build=profile["expected_build"],
         evaluation_terms_sha256=review["evaluation_terms_sha256"].lower())


def unzip_sdk(archive: Path, destination: Path) -> None:
    destination.mkdir()
    with zipfile.ZipFile(archive) as source:
        members = source.infolist()
        require(len(members) < 30000 and sum(x.file_size for x in members) < 4 * GIB, "sdk_zip_resource_limit")
        root = destination.resolve()
        for member in members:
            target = (root / member.filename).resolve()
            require(target.is_relative_to(root) and not stat.S_ISLNK(member.external_attr >> 16), "sdk_zip_path_rejected")
        source.extractall(root)
    require((destination / "dotnet.exe").is_file() and
            (destination / "shared/Microsoft.WindowsDesktop.App/8.0.33").is_dir() and
            (destination / "packs/Microsoft.WindowsDesktop.App.Ref/8.0.33").is_dir() and
            (destination / "sdk/8.0.427").is_dir(), "sdk_archive_not_complete_windowsdesktop")


def unattend(account: str, password: str, machine: str, image_index: int, owner_nonce: str = "0" * 48) -> bytes:
    require(re.fullmatch(r"[0-9A-Fa-f]{48}", owner_nonce) is not None, "answer_owner_nonce_invalid")
    def add(parent, tag, text=None, **attributes):
        element = ET.SubElement(parent, "{" + UNATTEND + "}" + tag, attributes)
        if text is not None:
            element.text = str(text)
        return element
    def component(settings, name):
        return add(settings, "component", name=name, processorArchitecture="amd64", publicKeyToken="31bf3856ad364e35",
                   language="neutral", versionScope="nonSxS")
    root = ET.Element("{" + UNATTEND + "}unattend")
    pe = add(root, "settings", pass_="windowsPE")
    pe.attrib = {"pass": "windowsPE"}
    locale = component(pe, "Microsoft-Windows-International-Core-WinPE")
    add(add(locale, "SetupUILanguage"), "UILanguage", "en-US")
    for key, value in {"InputLocale": "0409:00000409", "SystemLocale": "en-US", "UILanguage": "en-US", "UserLocale": "en-US"}.items():
        add(locale, key, value)
    setup = component(pe, "Microsoft-Windows-Setup")
    disks = add(setup, "DiskConfiguration")
    disk = add(disks, "Disk", **{"{" + WCM + "}action": "add"})
    add(disk, "DiskID", 0); add(disk, "WillWipeDisk", "true")
    create = add(disk, "CreatePartitions")
    # A single owned 64 GiB disk: EFI, MSR, Windows, and remaining recovery space.
    for order, kind, size in [(1, "EFI", 260), (2, "MSR", 16), (3, "Primary", 64000), (4, "Primary", None)]:
        part = add(create, "CreatePartition", **{"{" + WCM + "}action": "add"})
        add(part, "Order", order); add(part, "Type", kind)
        add(part, "Extend" if size is None else "Size", "true" if size is None else size)
    modify = add(disk, "ModifyPartitions")
    for order, partition, filesystem, label, letter in [(1, 1, "FAT32", "System", None), (2, 3, "NTFS", "Windows", "C"), (3, 4, "NTFS", "WindowsRE", None)]:
        part = add(modify, "ModifyPartition", **{"{" + WCM + "}action": "add"})
        for key, value in {"Order": order, "PartitionID": partition, "Format": filesystem, "Label": label}.items():
            add(part, key, value)
        if letter:
            add(part, "Letter", letter)
        if partition == 4:
            add(part, "TypeID", "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC")
    add(disks, "WillShowUI", "OnError")
    image = add(add(setup, "ImageInstall"), "OSImage")
    metadata = add(add(image, "InstallFrom"), "MetaData", **{"{" + WCM + "}action": "add"})
    add(metadata, "Key", "/IMAGE/INDEX"); add(metadata, "Value", image_index)
    target = add(image, "InstallTo"); add(target, "DiskID", 0); add(target, "PartitionID", 3)
    add(image, "WillShowUI", "OnError")
    add(add(setup, "UserData"), "AcceptEula", "true")
    special = add(root, "settings", **{"pass": "specialize"})
    shell = component(special, "Microsoft-Windows-Shell-Setup")
    add(shell, "ComputerName", machine); add(shell, "TimeZone", "UTC")
    deployment = component(special, "Microsoft-Windows-Deployment")
    synchronous = add(deployment, "RunSynchronous")
    # Configure only the two documented first-sign-in presentation policies on
    # this new fixture, before A or B first signs in. No account-registration,
    # authentication, licensing, TPM, or Secure Boot requirement is changed.
    policies = (
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableFirstLogonAnimation", 0),
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE", "DisablePrivacyExperience", 1),
    )
    for order, (key, value, data) in enumerate(policies, 1):
        entry = add(synchronous, "RunSynchronousCommand", **{"{" + WCM + "}action": "add"})
        add(entry, "Order", order)
        add(entry, "Description", "Configure owned fixture first-sign-in presentation")
        policy_command = f'%WINDIR%\\System32\\reg.exe add "{key}" /v {value} /t REG_DWORD /d {data} /f /reg:64'
        require(len(policy_command) <= 259, "specialize_command_too_long")
        add(entry, "Path", policy_command)
        add(entry, "WillReboot", "Never")
    oobe = add(root, "settings", **{"pass": "oobeSystem"})
    locale = component(oobe, "Microsoft-Windows-International-Core")
    for key, value in {"InputLocale": "0409:00000409", "SystemLocale": "en-US", "UILanguage": "en-US", "UserLocale": "en-US"}.items():
        add(locale, key, value)
    shell = component(oobe, "Microsoft-Windows-Shell-Setup")
    choices = add(shell, "OOBE"); add(choices, "HideEULAPage", "true"); add(choices, "ProtectYourPC", 1)
    local = add(add(add(shell, "UserAccounts"), "LocalAccounts"), "LocalAccount", **{"{" + WCM + "}action": "add"})
    secret = add(local, "Password"); add(secret, "Value", password); add(secret, "PlainText", "true")
    add(local, "Name", account); add(local, "Group", "Administrators"); add(local, "Description", "Disposable local API test parent")
    auto = add(shell, "AutoLogon")
    secret = add(auto, "Password"); add(secret, "Value", password); add(secret, "PlainText", "true")
    add(auto, "Enabled", "true"); add(auto, "LogonCount", 1); add(auto, "Username", account); add(auto, "Domain", machine)
    # One short ordinary first-logon command. Start-Process inherits the current
    # fresh administrator A token; no RunAs/SYSTEM/ExecutionPolicy alteration.
    # It returns immediately so Windows can finish displaying the desktop.
    bootstrap = ("$ErrorActionPreference='Stop'; $v=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=5'|"
                 "Where-Object VolumeName -eq 'SESSIONPAYLOAD'); if($v.Count -ne 1){exit 71}; "
                 "$r=$v[0].DeviceID+'\\'; if(!(Test-Path ($r+'guest-contract.tag'))){exit 72}; "
                 "Start-Process -FilePath ($r+'dotnet\\dotnet.exe') -ArgumentList @(($r+'GuestSupervisor.dll'),'--media-root',$r) "
                 "-WindowStyle Hidden")
    # FirstLogonCommands.CommandLine is limited to 1024 characters. Ordinary
    # -Command avoids UTF-16/Base64 expansion. ElementTree escapes XML syntax;
    # all fixed PowerShell literals use single quotes and contain no secrets.
    require('"' not in bootstrap, "first_logon_bootstrap_quoting_invalid")
    commandline = 'powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -Command "& { ' + bootstrap + ' }"'
    require(len(commandline) <= 1024, "first_logon_command_too_long")
    first = add(add(shell, "FirstLogonCommands"), "SynchronousCommand", **{"{" + WCM + "}action": "add"})
    add(first, "Order", 1); add(first, "Description", "Owned session fixture " + owner_nonce)
    add(first, "CommandLine", commandline)
    add(first, "RequiresUserInput", "false")
    data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    ET.fromstring(data)
    return data


def prepare_payload(work: Path, source: Path, supervisor: Path, profile: dict, sdk_archive: Path,
                    deadline: Deadline) -> tuple[Path, Path, str, str]:
    payload = work / "payload"
    payload.mkdir()
    unzip_sdk(sdk_archive, payload / "dotnet")
    require((source / "DisposableGuestReceipt.cs").is_file() and
            "DisposableGuestReceipt.IsRequested()" in (source / "OwnedTestAccount.cs").read_text(), "reviewed_guest_guard_not_integrated")
    require((source / "DisposableGuestReceipt.cs").read_bytes() == (HERE / "DisposableGuestReceipt.cs").read_bytes(),
            "guest_receipt_helper_version_mismatch")
    target = payload / "source"; target.mkdir()
    for file in sorted(source.iterdir()):
        if file.suffix in {".cs", ".csproj"}:
            require(file.is_file() and not file.is_symlink(), "test_source_not_regular")
            shutil.copyfile(file, target / file.name)
    for suffix in (".dll", ".deps.json", ".runtimeconfig.json"):
        file = supervisor / ("GuestSupervisor" + suffix)
        require(file.is_file(), "compiled_supervisor_missing")
        shutil.copyfile(file, payload / file.name)
    shutil.copyfile(HERE / "NuGet.Config", payload / "NuGet.Config")
    shutil.copyfile(HERE / "global.json", payload / "global.json")
    nonce = secrets.token_hex(24).upper()
    firmware_uuid = str(uuid.uuid4())
    account = "scga" + secrets.token_hex(6)
    password = "aA1!" + secrets.token_urlsafe(30)
    machine = "SCG-" + secrets.token_hex(4).upper()
    config = {"nonce": nonce, "firmware_uuid": firmware_uuid, "account_name": account,
              "edition": profile["expected_edition"], "build": profile["expected_build"]}
    (payload / "guest-config.json").write_text(json.dumps(config, separators=(",", ":")))
    (payload / "guest-contract.tag").write_text("owned-disposable-guest/v1\n")
    setup = work / "setup"; setup.mkdir()
    (setup / "Autounattend.xml").write_bytes(unattend(account, password, machine, profile["image_index"], nonce))
    # Credentials are confined to a separate setup CD. It is removed before B
    # can be created; the persistent payload CD contains no password or XML.
    password = ""
    setup_iso = work / "setup.iso"
    command(["xorriso", "-as", "mkisofs", "-quiet", "-J", "-R", "-V", "SESSIONSETUP",
             "-o", str(setup_iso), str(setup)], deadline, 60)
    shutil.rmtree(setup)
    iso = work / "payload.iso"
    command(["xorriso", "-as", "mkisofs", "-quiet", "-iso-level", "3", "-J", "-joliet-long", "-R", "-V", "SESSIONPAYLOAD",
             "-o", str(iso), str(payload)], deadline, 300)
    shutil.rmtree(payload)
    return iso, setup_iso, nonce, firmware_uuid


class Qmp:
    def __init__(self, path: Path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        self.socket.connect(str(path))
        self.file = self.socket.makefile("rwb", buffering=0)
        require("QMP" in self.read(), "qmp_greeting_invalid")
        self.number = 0
        self.call("qmp_capabilities")

    def read(self) -> dict:
        raw = self.file.readline(65537)
        require(raw.endswith(b"\n") and len(raw) <= 65536, "qmp_message_size_invalid")
        return json.loads(raw)

    def call(self, name: str, arguments: dict | None = None):
        self.number += 1
        request = {"execute": name, "id": self.number}
        if arguments is not None:
            request["arguments"] = arguments
        self.file.write(json.dumps(request, separators=(",", ":")).encode() + b"\r\n")
        end = time.monotonic() + 5
        while time.monotonic() < end:
            response = self.read()
            if response.get("id") == self.number:
                require("return" in response and "error" not in response, "qmp_command_failed")
                return response["return"]
        raise Failure("qmp_reply_timeout")

    def close(self):
        try:
            self.file.close()
        finally:
            self.socket.close()


def block_progress(qmp: Qmp) -> dict:
    try:
        entries = qmp.call("query-blockstats")
        require(isinstance(entries, list) and len(entries) <= 16, "block_statistics_invalid")
        result = {"query_succeeded": True}
        for key in ("rd_bytes", "wr_bytes", "rd_operations", "wr_operations"):
            values = [entry["stats"][key] for entry in entries]
            require(all(type(value) is int and 0 <= value < 2**63 for value in values), "block_statistics_invalid")
            result[key] = sum(values)
        return result
    except Exception:
        return {"query_succeeded": False}


def remove_setup_medium(qmp: Qmp, setup_iso: Path) -> None:
    # Guest resumes only after this exact own medium has been detached and its
    # host file removed. This avoids a guest race against an open, still-filled
    # tray. The payload and original installation CD are never selected here.
    qmp.call("stop")
    require(qmp.call("query-status").get("running") is False, "setup_detach_vm_not_paused")
    entries = qmp.call("query-block")
    selected = [entry for entry in entries if entry.get("device") == "answerbackend"]
    require(len(selected) == 1 and selected[0].get("qdev") == "setupcd" and selected[0].get("removable") is True and
            selected[0].get("inserted", {}).get("file") == str(setup_iso) and selected[0]["inserted"].get("ro") is True,
            "setup_medium_ownership_not_verified")
    qmp.call("blockdev-open-tray", {"id": "setupcd", "force": False})
    entries = qmp.call("query-block")
    selected = [entry for entry in entries if entry.get("device") == "answerbackend"]
    require(len(selected) == 1 and selected[0].get("tray_open") is True,
            "owned_setup_tray_not_open")
    qmp.call("blockdev-remove-medium", {"id": "setupcd"})
    entries = qmp.call("query-block")
    selected = [entry for entry in entries if entry.get("device") == "answerbackend"]
    require(len(selected) == 1 and selected[0].get("qdev") == "setupcd" and "inserted" not in selected[0] and
            selected[0].get("tray_open") is True, "owned_setup_medium_still_inserted")
    setup_iso.unlink()
    require(not setup_iso.exists(), "owned_setup_iso_not_removed")
    qmp.call("cont")
    require(qmp.call("query-status").get("running") is True, "guest_not_resumed_after_setup_detach")
    emit("owned_setup_medium_removed", setup_medium_detached=True, setup_host_file_removed=True, guest_resumed=True)


class SerialReader:
    HELLO_PREFIX = b"\nGUEST_HELLO_V1 "
    MAX_NOISE_BYTES = 65536
    MAX_PRE_HELLO_SECONDS = 50 * 60
    NOISE_MARKERS = ((b"\x1b[", "ansi_escape"), (b"bdsdxe", "bdsdxe_marker"),
                     (b"uefi", "uefi_marker"), (b"tianocore", "tianocore_marker"),
                     (b"press any key", "press_any_key_marker"))

    def __init__(self, nonce: str):
        require(re.fullmatch(r"[0-9A-Fa-f]{48}", nonce) is not None, "serial_nonce_invalid")
        self.nonce = nonce
        self.buffer = bytearray()
        self.length = None
        self.digest = None
        self.result = None
        self.phases = 0
        self.received = 0
        self.hello_verified = False
        self.noise_started = time.monotonic()
        self.noise_bytes = 0
        self.noise_tail = b""
        self.noise_categories = set()
        self.activation_count = 0
        self.activation_iteration = 0
        self.activation_step = -1
        self.activation_pending = []

    def _activation(self, values: tuple[int, ...]) -> None:
        iteration, step, code, count, status, reason = values
        require(1 <= iteration <= 18 and 0 <= step <= 8 and -(2**31) <= code < 2**31 and
                -1 <= count <= 512 and -1 <= status <= 6 and -1 <= reason < 2**32,
                "activation_observation_range_invalid")
        new_iteration = iteration == self.activation_iteration + 1 and step == 0 and self.activation_step in {-1, 7}
        next_step = iteration == self.activation_iteration and (step == self.activation_step + 1 or
                    (step == 8 and 0 <= self.activation_step < 8))
        require(new_iteration or next_step, "activation_observation_order_invalid")
        if step == 7:
            require(count >= 0 and code == 0 and ((count == 1 and status >= 0 and reason >= 0) or
                    (count != 1 and status == -1 and reason == -1)), "activation_parsed_observation_invalid")
        else:
            require(count == -1 and status == -1 and reason == -1 and (code == 0 or step in {5, 6, 8}),
                    "activation_process_observation_invalid")
        self.activation_count += 1
        require(self.activation_count <= 192, "activation_observation_limit")
        self.activation_iteration, self.activation_step = iteration, step
        self.activation_pending.append({"iteration": iteration, "step": step, "code": code,
            "candidate_count": count, "license_status": status, "license_status_reason": reason})

    def take_activation_observations(self) -> list[dict]:
        result, self.activation_pending = self.activation_pending, []
        return result

    def _classify_noise(self, data: bytes) -> set[str]:
        lowered = data.lower()
        return {category for marker, category in self.NOISE_MARKERS if marker in lowered}

    def _note_noise(self, data: bytes) -> None:
        total = self.noise_bytes + len(data)
        require(total <= self.MAX_NOISE_BYTES, "serial_noise_limit")
        self.noise_bytes = total
        combined = self.noise_tail + data
        self.noise_categories.update(self._classify_noise(combined))
        self.noise_tail = combined[-64:]

    def startup_observation(self) -> dict:
        # Only byte counts and fixed marker categories are public. Markers do
        # not establish their emitter, a particular screen, or Windows boot.
        pending = b"" if self.hello_verified else bytes(self.buffer)
        categories = self.noise_categories | self._classify_noise(self.noise_tail + pending)
        return {"hello_verified": self.hello_verified, "pre_hello_bytes": self.noise_bytes + len(pending),
                "marker_categories": sorted(categories)}

    def _accept_hello(self) -> bool:
        require(time.monotonic() - self.noise_started < self.MAX_PRE_HELLO_SECONDS, "serial_hello_timeout")
        position = self.buffer.find(self.HELLO_PREFIX)
        if position < 0:
            # Retain only enough bytes to recognize a prefix split between two
            # reads; the rest is bounded, classified noise, never API evidence.
            discard = max(0, len(self.buffer) - len(self.HELLO_PREFIX) + 1)
            if discard:
                self._note_noise(bytes(self.buffer[:discard]))
                del self.buffer[:discard]
            return False
        if position:
            self._note_noise(bytes(self.buffer[:position]))
            del self.buffer[:position]
        ending = self.buffer.find(b"\n", len(self.HELLO_PREFIX))
        if ending < 0:
            require(len(self.buffer) <= len(self.HELLO_PREFIX) + 48, "serial_hello_size_invalid")
            return False
        supplied = bytes(self.buffer[len(self.HELLO_PREFIX):ending])
        require(supplied == self.nonce.encode("ascii"), "serial_hello_binding_invalid")
        del self.buffer[:ending + 1]
        self.hello_verified = True
        return True

    def feed(self, data: bytes) -> list[str]:
        self.received += len(data)
        require(self.received <= 2 * 1024 * 1024 and len(self.buffer) + len(data) <= 131072, "serial_resource_limit")
        require(self.result is None or not data.strip(), "serial_data_after_result")
        self.buffer.extend(data)
        if not self.hello_verified and not self._accept_hello():
            return []
        stages = []
        while self.buffer:
            if self.length is not None:
                if len(self.buffer) < self.length + 1:
                    break
                body = bytes(self.buffer[:self.length])
                require(self.buffer[self.length] == 10 and hashlib.sha256(body).hexdigest().upper() == self.digest, "serial_result_digest_or_ending_invalid")
                value = json.loads(body.decode("utf-8"))
                require(isinstance(value, dict) and value.get("schema") == "windows-guest-session-result/v1" and
                        value.get("nonce") == self.nonce, "serial_result_binding_invalid")
                require(self.result is None, "duplicate_serial_result")
                self.result = value
                del self.buffer[:self.length + 1]
                self.length = None
                require(not self.buffer.strip(), "serial_trailing_data")
                break
            position = self.buffer.find(b"\n")
            if position < 0:
                require(len(self.buffer) <= 256, "serial_header_limit")
                break
            line = bytes(self.buffer[:position]).rstrip(b"\r")
            del self.buffer[:position + 1]
            phase = re.fullmatch(rb"GUEST_PHASE_V1 ([a-z0-9_]{1,100})", line)
            header = re.fullmatch(rb"GUEST_RESULT_V1 ([0-9]{1,5}) ([0-9A-F]{64})", line)
            activation = re.fullmatch(rb"GUEST_ACTIVATION_V1 ([0-9]{1,2}) ([0-9]) (-?[0-9]{1,10}) (-?[0-9]{1,3}) (-?[0-9]) (-?[0-9]{1,10})", line)
            if phase:
                self.phases += 1
                require(self.phases <= 32, "serial_phase_limit")
                stages.append(phase.group(1).decode("ascii"))
            elif header:
                self.length = int(header.group(1)); self.digest = header.group(2).decode("ascii")
                require(0 < self.length <= 65536, "serial_result_length_invalid")
            elif activation:
                self._activation(tuple(map(int, activation.groups())))
            else:
                raise Failure("unexpected_serial_frame")
        return stages


def activation_audit_projection(value):
    """Validate and copy only bounded fixed fields; never forward provider text."""
    if value is None:
        return None
    def shape(item, fields):
        require(isinstance(item, dict) and set(item) == set(fields), "activation_audit_shape_invalid")
    def integer(item, minimum, maximum):
        return type(item) is int and minimum <= item <= maximum
    def boolean(item):
        return type(item) is bool
    def nullable_int(item, minimum, maximum):
        return item is None or integer(item, minimum, maximum)
    def license_snapshot(item):
        if item is None:
            return None
        names = ("candidate_count", "license_status", "license_status_reason", "grace_period_remaining",
                 "evaluation_end_utc", "trusted_time_utc", "guest_utc", "evaluation_expired")
        shape(item, names)
        require(integer(item["candidate_count"], 0, 512) and integer(item["guest_utc"], 946684800, 4102444800),
                "activation_license_identity_shape_invalid")
        if item["candidate_count"] != 1:
            require(type(item["license_status"]) is int and item["license_status"] == -1 and
                    type(item["license_status_reason"]) is int and item["license_status_reason"] == -1 and
                    all(item[key] is None for key in ("grace_period_remaining", "evaluation_end_utc", "trusted_time_utc", "evaluation_expired")),
                    "activation_license_ambiguous_values")
        else:
            require(integer(item["license_status"], 0, 6) and integer(item["license_status_reason"], 0, 2**32 - 1) and
                    nullable_int(item["grace_period_remaining"], 0, 2**32 - 1) and
                    all(nullable_int(item[key], 1, 253402300799) for key in ("evaluation_end_utc", "trusted_time_utc")),
                    "activation_license_numbers_invalid")
            end, trusted = item["evaluation_end_utc"], item["trusted_time_utc"]
            expired = None if end is None else end <= item["guest_utc"] or (trusted is not None and end <= trusted)
            require(item["evaluation_expired"] is expired, "activation_evaluation_expiry_inconsistent")
        return {key: item[key] for key in names}
    fields = ("before", "after", "network", "attempt_count", "method_process_started", "method_process_completed",
              "method_process_exit_code", "method_reply", "same_product_verified", "licensed_status_confirmed")
    shape(value, fields)
    require(integer(value["attempt_count"], 0, 1) and
            all(boolean(value[key]) for key in ("method_process_started", "method_process_completed", "same_product_verified", "licensed_status_confirmed")) and
            nullable_int(value["method_process_exit_code"], -(2**31), 2**31 - 1), "activation_audit_values_invalid")
    before, after = license_snapshot(value["before"]), license_snapshot(value["after"])
    network = value["network"]
    if network is not None:
        require(isinstance(network, list) and len(network) == 2, "activation_network_count_invalid")
        copied = []
        for index, item in enumerate(network, 1):
            names = ("endpoint_id", "dns_succeeded", "tcp_succeeded", "tls_succeeded", "error_hresult")
            shape(item, names)
            require(type(item["endpoint_id"]) is int and item["endpoint_id"] == index and
                    all(boolean(item[key]) for key in ("dns_succeeded", "tcp_succeeded", "tls_succeeded")) and
                    nullable_int(item["error_hresult"], -(2**31), 2**31 - 1) and
                    (not item["tls_succeeded"] or item["tcp_succeeded"]) and
                    (not item["tcp_succeeded"] or item["dns_succeeded"]) and
                    (item["error_hresult"] is not None or item["tls_succeeded"]), "activation_network_values_invalid")
            copied.append({key: item[key] for key in names})
        network = copied
    reply = value["method_reply"]
    if reply is not None:
        names = ("invocation_started", "invocation_returned", "return_value", "error_hresult", "guard_code", "same_product_verified",
                 "result_shape", "result_error_hresult")
        shape(reply, names)
        require(all(boolean(reply[key]) for key in ("invocation_started", "invocation_returned", "same_product_verified")) and
                integer(reply["guard_code"], 0, 4) and integer(reply["result_shape"], 0, 6) and
                nullable_int(reply["return_value"], 0, 2**32 - 1) and
                all(nullable_int(reply[key], -(2**31), 2**31 - 1) for key in ("error_hresult", "result_error_hresult")),
                "activation_method_values_invalid")
        started, returned, guard, same = (reply[key] for key in ("invocation_started", "invocation_returned", "guard_code", "same_product_verified"))
        rv, error = reply["return_value"], reply["error_hresult"]
        result_shape, result_error = reply["result_shape"], reply["result_error_hresult"]
        require(not ((started and (guard != 0 or not same)) or (not started and returned) or (rv is not None and not returned) or
                (not started and rv is not None) or (started and not returned and error is None) or
                (returned and error is not None) or (guard == 4 and error is None) or
                (guard in {1, 2} and (not same or started or error is not None)) or (guard == 3 and (same or started or error is not None)) or
                (guard == 0 and not started) or (returned != (result_shape != 0)) or
                ((rv is not None) != (result_shape == 3)) or ((result_error is not None) != (result_shape == 6))),
                "activation_method_reply_inconsistent")
        reply = {key: reply[key] for key in names}
    started, completed, code = (value[key] for key in ("method_process_started", "method_process_completed", "method_process_exit_code"))
    require((not completed or started) and (completed == (code is not None)) and
            (reply is None or (completed and code == 0)) and
            (value["attempt_count"] != 0 or (not started and not completed and reply is None)), "activation_process_evidence_inconsistent")
    return dict(before=before, after=after, network=network, attempt_count=value["attempt_count"],
                method_process_started=started, method_process_completed=completed, method_process_exit_code=code,
                method_reply=reply, same_product_verified=value["same_product_verified"], licensed_status_confirmed=value["licensed_status_confirmed"])


def licensed_audit(value) -> bool:
    try:
        audit = activation_audit_projection(value)
    except Failure:
        return False
    if audit is None or not audit["same_product_verified"] or not audit["licensed_status_confirmed"]:
        return False
    before, after = audit["before"], audit["after"]
    if before is None or after is None or before["candidate_count"] != 1 or after["candidate_count"] != 1 or after["license_status"] != 1 or \
            before["evaluation_expired"] is True or after["evaluation_expired"] is True:
        return False
    if audit["attempt_count"] == 0:
        return before["license_status"] == 1 and before == after
    reply = audit["method_reply"]
    return (before["license_status"] != 1 and audit["network"] is not None and audit["method_process_started"] and
            audit["method_process_completed"] and audit["method_process_exit_code"] == 0 and reply is not None and
            reply["same_product_verified"] and reply["error_hresult"] is None and reply["guard_code"] in {0, 1} and
            (not reply["invocation_started"] or reply["invocation_returned"]))


def successful_session_contract(value) -> bool:
    required = ("window_input_requested", "window_input_verified", "window_input_cleanup_verified",
                "window_child_received_expected_text", "window_child_received_expected_button_sequence",
                "frame_challenge_verified", "different_account_verified", "parent_and_child_active",
                "child_matches_created_account_sid", "witness_in_expected_session", "witness_identity_matches",
                "alternate_test_account_requested", "test_account_created", "test_account_non_administrator_verified", "test_credentials_applied",
                "child_removed", "enable_state_restored", "task_removed", "task_instances_stopped", "test_account_removed",
                "witness_sandbox_removed", "parent_still_active_after_cleanup", "console_session_unchanged",
                "child_search_preparation_cleanup_verified")
    excluded = ("direct_input_requested", "direct_input_channel_verified", "physical_input_isolation_verified",
                "native_multiseat_verified", "same_user_sid", "witness_administrator_group_present", "child_search_preparation_requested")
    return (isinstance(value, dict) and value.get("schema") == "session-contract-experiment/v1" and
            value.get("status") == "different_account_child_frame_and_window_input_verified" and
            all(value.get(key) is True for key in required) and all(value.get(key) is False for key in excluded))


def successful_result(value: dict) -> bool:
    required = ("guest_identity_verified", "elevated", "interactive_console_verified", "secure_boot_verified", "tpm2_verified",
                "fixture_presentation_verified", "activation_licensed_observed", "offline_runtime_verified", "harness_compiled", "autologon_disabled",
                "setup_media_was_readable", "setup_media_unavailable_verified", "cached_answer_files_absent_verified",
                "harness_cleanup_verified", "guest_work_directories_removed")
    test = value.get("test", {})
    power = value.get("power_request", {})
    activation = value.get("activation_observation", {})
    return (value.get("status") == "verified" and type(value.get("test_exit_code")) is int and value["test_exit_code"] == 0 and
            value.get("cleanup_unverified") is False and all(value.get(key) is True for key in required) and
            value.get("physical_input_isolation_verified") is False and value.get("native_multiseat_verified") is False and
            isinstance(power, dict) and power.get("acquired") is True and power.get("cleanup_verified") is True and
            isinstance(activation, dict) and type(activation.get("candidate_count")) is int and activation["candidate_count"] == 1 and
            type(activation.get("license_status")) is int and activation["license_status"] == 1 and activation.get("step") == 7 and
            licensed_audit(value.get("activation_audit")) and successful_session_contract(test))


def stop_owned(process: subprocess.Popen | None) -> bool:
    if process is None:
        return True
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                return False
    return process.poll() is not None


def execute(args) -> int:
    require(bool(os.environ.get("RUNNER_TEMP")), "runner_temp_missing")
    parent = Path(os.environ["RUNNER_TEMP"]).resolve()
    require(parent.is_dir() and parent != Path("/"), "runner_temp_invalid")
    preflight(parent)
    document, profile, sdk = load_media()
    require_media_facts(document, profile)
    deadline = Deadline()
    work = Path(tempfile.mkdtemp(prefix="session-guest-", dir=parent))
    os.chmod(work, 0o700)
    qemu = tpm = None
    qmp = None
    reader = None
    logs = []
    outcome = 1
    cleanup = False
    try:
        # QEMU's comma-separated option values do not accept arbitrary paths.
        # GitHub's known temporary path format is checked, never interpolated
        # through a shell or silently reinterpreted as another option.
        require(re.fullmatch(r"[A-Za-z0-9_./-]+", str(work)) is not None, "runner_temp_qemu_path_unsupported")
        emit("install_official_ubuntu_tools")
        command(["apt-get", "update", "-qq"], deadline, 600)
        command(["apt-get", "install", "--yes", "--no-install-recommends", "-o", "Dpkg::Use-Pty=0",
                 "qemu-system-x86", "qemu-utils", "ovmf", "swtpm", "swtpm-tools", "xorriso", "p7zip-full", "wimtools",
                 "tesseract-ocr", "tesseract-ocr-eng"], deadline, 600)
        descriptor = Path("/usr/share/qemu/firmware/40-edk2-x86_64-secure-enrolled.json")
        firmware = json.loads(descriptor.read_text())
        require({"secure-boot", "enrolled-keys", "requires-smm"}.issubset(set(firmware["features"])), "ms_secure_firmware_features_missing")
        code = Path(firmware["mapping"]["executable"]["filename"])
        variables = Path(firmware["mapping"]["nvram-template"]["filename"])
        require(code.name in {"OVMF_CODE_4M.ms.fd", "OVMF_CODE_4M.secboot.fd"} and variables.name == "OVMF_VARS_4M.ms.fd" and
                code.is_file() and variables.is_file(), "ms_secure_firmware_mapping_changed")
        shutil.copyfile(variables, work / "OVMF_VARS.fd")
        emit("firmware_selected", code_sha256=sha(code), variables_template_sha256=sha(variables))
        iso = work / "windows.iso"
        emit("download_official_evaluation_media")
        digest = download(profile["url"], iso, deadline, expected_length=profile["bytes"], expected_digest=profile["sha256"],
                          algorithm="sha256", expected_url=profile["final_url"], maximum_bytes=9 * GIB)
        emit("iso_download_verified", iso_sha256=digest, bytes=iso.stat().st_size, microsoft_published_digest_compared=profile["sha256"] is not None)
        verify_media(iso, profile, document["license_review"], work, deadline)
        sdk_zip = work / "sdk.zip"
        emit("download_pinned_windows_sdk")
        download(sdk["url"], sdk_zip, deadline, expected_length=None, expected_digest=sdk["hash"], algorithm="sha512",
                 expected_url=sdk["url"], maximum_bytes=GIB)
        emit("sdk_sha512_verified", sdk_version=sdk["version"])
        payload, setup_iso, nonce, guest_uuid = prepare_payload(work, Path(args.source).resolve(), Path(args.supervisor).resolve(), profile, sdk_zip, deadline)
        sdk_zip.unlink()
        require(shutil.disk_usage(work).free >= 66 * GIB, "disk_reserve_after_payload_insufficient")
        disk = work / "guest.qcow2"
        command(["qemu-img", "create", "-q", "-f", "qcow2", str(disk), "64G"], deadline, 30)
        tpm_dir = work / "tpm"; tpm_dir.mkdir()
        command(["swtpm_setup", "--tpm2", "--tpmstate", str(tpm_dir), "--create-ek", "--lock-nvram", "--not-overwrite"], deadline, 60)
        tpm_log = (work / "swtpm.log").open("wb"); logs.append(tpm_log)
        tpm_socket = work / "tpm.sock"
        tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + str(tpm_dir),
                                "--ctrl", "type=unixio,path=" + str(tpm_socket), "--flags", "not-need-init"],
                               stdin=subprocess.DEVNULL, stdout=tpm_log, stderr=tpm_log)
        start = time.monotonic()
        while not tpm_socket.exists():
            require(tpm.poll() is None and time.monotonic() - start < 15, "owned_tpm_socket_unavailable")
            time.sleep(0.1)
        serial_path = work / "serial.out"
        qmp_path = work / "qmp.sock"
        qemu_log = (work / "qemu.log").open("wb"); logs.append(qemu_log)
        arguments = ["qemu-system-x86_64", "-no-user-config", "-nodefaults", "-machine", "q35,smm=on,dump-guest-core=off",
                     "-accel", "kvm", "-cpu", "host", "-smp", "4,sockets=1,cores=4,threads=1", "-m", "8192", "-uuid", guest_uuid,
                     "-global", "driver=cfi.pflash01,property=secure,value=on", "-global", "ICH9-LPC.disable_s3=1",
                     "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
                     "-drive", f"if=pflash,format=raw,unit=1,file={work / 'OVMF_VARS.fd'}",
                     "-device", "ich9-ahci,id=sata", "-drive", f"if=none,id=osdisk,format=qcow2,file={disk}",
                     "-device", "ide-hd,drive=osdisk,bus=sata.0", "-drive", f"if=none,id=install,format=raw,media=cdrom,readonly=on,file={iso}",
                     "-device", "ide-cd,drive=install,bus=sata.1", "-drive", f"if=none,id=payload,format=raw,media=cdrom,readonly=on,file={payload}",
                     "-device", "ide-cd,drive=payload,bus=sata.2", "-boot", "order=c,once=d,menu=off",
                     "-drive", f"if=none,id=answerbackend,format=raw,media=cdrom,readonly=on,file={setup_iso}",
                     "-device", "ide-cd,id=setupcd,drive=answerbackend,bus=sata.3",
                     "-device", "VGA,vgamem_mb=16", "-display", "none", "-monitor", "none", "-parallel", "none",
                     "-netdev", "user,id=nat", "-device", "e1000e,netdev=nat", "-rtc", "base=utc",
                     "-chardev", f"socket,id=chrtpm,path={tpm_socket}", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                     "-device", "tpm-crb,tpmdev=tpm0", "-chardev", f"file,id=serial0,path={serial_path}",
                     "-device", "isa-serial,chardev=serial0,index=0", "-qmp", f"unix:{qmp_path},server=on,wait=off", "-S"]
        require(arguments.count("kvm") == 1 and "tcg" not in " ".join(arguments) and "hostfwd" not in " ".join(arguments), "qemu_accel_or_port_invariant")
        qemu = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=qemu_log, stderr=qemu_log)
        start = time.monotonic()
        while not qmp_path.exists():
            require(qemu.poll() is None and time.monotonic() - start < 20, "owned_qmp_unavailable")
            time.sleep(0.1)
        qmp = Qmp(qmp_path)
        kvm = qmp.call("query-kvm")
        require(kvm.get("enabled") is True and kvm.get("present") is True, "qemu_kvm_not_actually_enabled")
        emit("qemu_kvm_verified", guest_ram_mib=8192, disk_virtual_gib=64, cpu_count=4, public_port_forwarding=False)
        reader = SerialReader(nonce)
        offset = 0
        boot_start = time.monotonic()
        first_logon = None
        setup_detached = False
        hello_reported = False
        activation_started = None
        activation_finished = False

        def observe_serial() -> None:
            nonlocal offset, first_logon, setup_detached, hello_reported, activation_started, activation_finished
            block = b""
            if serial_path.exists():
                with serial_path.open("rb") as file:
                    file.seek(offset)
                    block = file.read(65536)
                offset += len(block)
            phases = reader.feed(block)
            if reader.hello_verified and not hello_reported:
                hello_reported = True
                first_logon = time.monotonic()
                emit("serial_hello_verified", **reader.startup_observation())
            for phase in phases:
                emit("guest_phase", phase=phase)
                if phase == "setup_media_detach_requested":
                    require(not setup_detached, "duplicate_setup_detach_request")
                    remove_setup_medium(qmp, setup_iso)
                    setup_detached = True
                elif phase == "awaiting_standard_activation":
                    require(activation_started is None and not activation_finished, "duplicate_activation_phase")
                    activation_started = time.monotonic()
                elif phase == "standard_activation_observed":
                    require(activation_started is not None and not activation_finished, "activation_phase_order_invalid")
                    activation_finished = True
                    activation_started = None
            for observation in reader.take_activation_observations():
                emit("guest_activation_observation", **observation)

        qmp.call("cont")
        # Only the initial, owned VM boot gets a finite space-key burst for
        # Microsoft's stock CD prompt. No bootloader patch or OS check bypass.
        # Missing the prompt remains a real first-logon timeout, never a pass.
        for _ in range(24):
            require(qemu.poll() is None, "qemu_exited_during_initial_boot")
            observe_serial()
            if reader.hello_verified:
                break
            qmp.call("send-key", {"keys": [{"type": "qcode", "data": "spc"}], "hold-time": 60})
            time.sleep(0.5)
        emit("initial_cd_boot_keys_complete")
        next_heartbeat = boot_start
        while reader.result is None:
            deadline.seconds(1)
            require(qemu.poll() is None, "qemu_exited_without_result")
            require(time.monotonic() - boot_start < 50 * 60, "guest_install_or_test_timeout")
            if first_logon is not None:
                require(time.monotonic() - first_logon < 20 * 60, "guest_supervisor_timeout")
            if activation_started is not None:
                require(time.monotonic() - activation_started < 270, "guest_activation_phase_timeout")
            require(shutil.disk_usage(work).free >= 3 * GIB, "host_disk_reserve_exhausted")
            require((work / "qemu.log").stat().st_size <= 2 * 1024 * 1024 and (work / "swtpm.log").stat().st_size <= 2 * 1024 * 1024,
                    "hypervisor_log_limit")
            observe_serial()
            if time.monotonic() >= next_heartbeat:
                emit("awaiting_guest", first_logon_observed=first_logon is not None,
                     elapsed_seconds=int(time.monotonic() - boot_start), vm_state=failure_diagnostics.query_state(qmp), storage=block_progress(qmp),
                     serial_startup=reader.startup_observation())
                next_heartbeat = time.monotonic() + 30
            time.sleep(0.25)
        value = reader.result
        # The per-run binding nonce is checked but excluded from public output.
        public_fields = ("schema", "status", "stage", "guest_identity_verified", "elevated", "interactive_console_verified",
                         "secure_boot_verified", "tpm2_verified", "fixture_presentation_verified", "first_logon_animation_value",
                         "privacy_experience_value", "setup_media_was_readable", "setup_media_unavailable_verified",
                         "setup_media_read_error_code", "cached_answer_files_removed", "cached_answer_files_absent_verified",
                         "activation_licensed_observed", "activation_observation", "power_request", "offline_runtime_verified",
                         "harness_compiled", "autologon_disabled", "harness_cleanup_verified", "guest_work_directories_removed",
                         "cleanup_unverified", "physical_input_isolation_verified", "native_multiseat_verified",
                         "test_exit_code", "test", "error_type", "failure_code", "error_hresult")
        public = {key: value[key] for key in public_fields if key in value}
        if "activation_audit" in value:
            public["activation_audit"] = activation_audit_projection(value["activation_audit"])
        emit("guest_result", result=public)
        outcome = 0 if setup_detached and successful_result(value) else 1
    finally:
        cleanup_errors = []
        if reader is not None:
            emit("serial_startup_observation", **reader.startup_observation())
        if qmp is not None:
            if outcome != 0 and qemu is not None and qemu.poll() is None:
                try:
                    emit("guest_failure_observation", **failure_diagnostics.observe_failure(qmp, work, deadline, command))
                except Exception:
                    emit("guest_failure_observation", diagnostic_only=True, diagnostic_category="observation_unavailable")
            try:
                qmp.call("quit")
            except Exception:
                # Quitting via QMP is best-effort; owned-process termination
                # below is authoritative and must still run after any error.
                pass
            try:
                qmp.close()
            except Exception:
                cleanup_errors.append("qmp_close")
        qemu_stopped = tpm_stopped = False
        try:
            qemu_stopped = stop_owned(qemu)
        except Exception:
            cleanup_errors.append("qemu_stop")
        try:
            tpm_stopped = stop_owned(tpm)
        except Exception:
            cleanup_errors.append("swtpm_stop")
        for log in logs:
            try:
                log.close()
            except Exception:
                cleanup_errors.append("log_close")
        for process, name in ((qemu, "qemu"), (tpm, "swtpm")):
            if process is not None:
                try:
                    with (work / (name + ".log")).open("rb") as log:
                        diagnostic = diagnostic_category(log.read(16384))
                    emit("owned_process_exit", process=name, exit_code=process.poll(), diagnostic_category=diagnostic)
                except Exception:
                    emit("owned_process_exit", process=name, exit_code=process.poll(), diagnostic_category="unavailable")
        if qemu_stopped and tpm_stopped:
            try:
                shutil.rmtree(work)
                cleanup = not work.exists()
            except Exception:
                cleanup_errors.append("own_directory_remove")
        emit("host_cleanup", own_qemu_stopped=qemu_stopped, own_swtpm_stopped=tpm_stopped,
             own_resources_removed=cleanup, cleanup_errors=cleanup_errors, cleanup_unverified=not cleanup or bool(cleanup_errors))
    return outcome if cleanup and not cleanup_errors else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--source", default=str(HERE.parent / "session/child"))
    parser.add_argument("--supervisor", default=str(HERE / "build"))
    args = parser.parse_args()
    try:
        if not args.execute:
            document, profile, _ = load_media()
            require_media_facts(document, profile)
            xml = unattend("scgadryrun001", "TemporaryDryRunPassword1!", "SCG-DRYRUN", 1)
            require(ET.fromstring(xml).tag == "{" + UNATTEND + "}unattend", "unattend_syntax_invalid")
            emit("dry_run", no_downloads=True, no_guest_executed=True, autounattend_xml_parsed=True,
                 selected_profile=document["selected_profile"], iso_expected_bytes=profile["bytes"],
                 evaluation_terms_sha256=document["license_review"]["evaluation_terms_sha256"],
                 guest_ram_mib=8192, disk_virtual_gib=64, accelerator="kvm_only", job_timeout_minutes=90)
            return 0
        def terminate(signum, frame):
            raise Failure("host_termination_requested", signum)
        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGINT, terminate)
        return execute(args)
    except Failure as failure:
        emit("failed", operation=failure.stage, code=failure.code, diagnostic_category=failure.diagnostic)
        return 1
    except Exception as exception:
        # No exception message/argv/XML is printed: it could contain a private
        # temporary path or credential-bearing setup media content.
        emit("failed", exception_type=type(exception).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
