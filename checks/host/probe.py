#!/usr/bin/env python3
"""Read-only hosted-Linux inventory; this is not a Windows/VM success test.

No network, subprocesses, writes, device creation, permission changes, or
KVM_CREATE_VM. Only KVM_GET_API_VERSION is issued, on an O_RDONLY descriptor.
Paths, account identities, environment values and exception text are not emitted.
"""

import argparse
import datetime
import errno
import fcntl
import json
import os
import pathlib
import platform
import shutil
import stat


SCHEMA = "windows-ci-host-preflight/v1"
KVM_GET_API_VERSION = 0xAE00  # Linux UAPI: _IO(KVMIO=0xAE, 0x00).
CGROUP_ROOT = pathlib.Path("/sys/fs/cgroup")
MAX_CGROUP_DEPTH = 32


def failure(exc, availability="unavailable"):
    return {"availability": availability, "errno": int(getattr(exc, "errno", 0) or 0)}


def read_text(path, limit=65536):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise OSError(errno.EFBIG, "bounded read exceeded")
    return data.decode("ascii", errors="strict")


def unsigned(text):
    if not text.isascii() or not text.isdecimal() or len(text) > 20:
        raise ValueError("invalid unsigned integer")
    value = int(text)
    if value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("integer out of range")
    return value


def kvm_probe():
    result = {
        "availability": "unavailable", "present": False,
        "character_device": False, "read_access": False, "write_access": False,
        "opened_read_only": False, "api_version": None, "api_version_supported": False,
        "vm_creation_tested": False, "errno": 0,
    }
    descriptor = None
    try:
        info = os.lstat("/dev/kvm")
        result["present"] = True
        result["character_device"] = stat.S_ISCHR(info.st_mode)
        result["read_access"] = os.access("/dev/kvm", os.R_OK, effective_ids=True)
        result["write_access"] = os.access("/dev/kvm", os.W_OK, effective_ids=True)
        if not result["character_device"]:
            result["availability"] = "not_character_device"
            return result
        descriptor = os.open("/dev/kvm", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        result["opened_read_only"] = True
        version = fcntl.ioctl(descriptor, KVM_GET_API_VERSION, 0)
        result["api_version"] = version
        result["api_version_supported"] = version == 12
        result["availability"] = "available" if version == 12 else "unsupported_api"
    except (OSError, ValueError, UnicodeError) as exc:
        result.update(failure(exc))
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result


def cpu_probe():
    result = {"logical_cpu_count": os.cpu_count(), "affinity_cpu_count": None,
              "vmx": None, "svm": None, "availability": "available", "errno": 0}
    try:
        result["affinity_cpu_count"] = len(os.sched_getaffinity(0))
        flags = set()
        for line in read_text("/proc/cpuinfo", 4 * 1024 * 1024).splitlines():
            name, separator, value = line.partition(":")
            if separator and name.strip() in ("flags", "Features"):
                flags.update(value.split())
        result["vmx"] = "vmx" in flags
        result["svm"] = "svm" in flags
    except (OSError, ValueError, UnicodeError) as exc:
        result.update(failure(exc))
    return result


def memory_probe():
    try:
        values = {}
        for line in read_text("/proc/meminfo").splitlines():
            name, separator, rest = line.partition(":")
            if separator and name in ("MemTotal", "MemAvailable"):
                parts = rest.split()
                if len(parts) != 2 or parts[1] != "kB":
                    raise ValueError("unexpected memory unit")
                values[name] = unsigned(parts[0]) * 1024
        if set(values) != {"MemTotal", "MemAvailable"}:
            raise ValueError("missing memory fields")
        return {"availability": "available", "total_bytes": values["MemTotal"],
                "available_bytes": values["MemAvailable"], "errno": 0}
    except (OSError, ValueError, UnicodeError) as exc:
        return failure(exc)


def cgroup_probe():
    result = {"availability": "unavailable", "version": None, "hierarchy_complete": False,
              "levels_read": 0, "cpu_files_read": 0, "memory_files_read": 0,
              "cpu_quota_state": "unknown", "cpu_quota_upper_bound_cores": None,
              "memory_limit_bytes": None, "memory_headroom_bytes": None,
              "errors": []}
    try:
        memberships = read_text("/proc/self/cgroup").splitlines()
        entries = [line.split(":", 2) for line in memberships]
        matches = [entry[2] for entry in entries if len(entry) == 3 and entry[0] == "0" and entry[1] == ""]
        if len(matches) != 1:
            result["availability"] = "unsupported_layout"
            result["version"] = 1 if entries else None
            return result
        result["version"] = 2
        membership = pathlib.PurePosixPath(matches[0])
        if not membership.is_absolute() or ".." in membership.parts:
            raise ValueError("invalid cgroup membership")
        current = CGROUP_ROOT.joinpath(*membership.parts[1:])
        if not current.is_dir():
            result["availability"] = "membership_not_visible"
            return result
        cpu_limits, memory_limits, headrooms = [], [], []
        for _ in range(MAX_CGROUP_DEPTH):
            result["levels_read"] += 1
            for filename in ("cpu.max", "memory.max"):
                try:
                    fields = read_text(current / filename, 256).split()
                    if filename == "cpu.max":
                        if len(fields) != 2:
                            raise ValueError("invalid cpu quota")
                        period = unsigned(fields[1])
                        if period == 0:
                            raise ValueError("invalid cpu period")
                        if fields[0] != "max":
                            quota = unsigned(fields[0])
                            if quota == 0:
                                raise ValueError("invalid cpu quota")
                            cpu_limits.append(quota / period)
                        result["cpu_files_read"] += 1
                    else:
                        if len(fields) != 1:
                            raise ValueError("invalid memory limit")
                        if fields[0] != "max":
                            limit = unsigned(fields[0])
                            memory_limits.append(limit)
                            used = unsigned(read_text(current / "memory.current", 256).strip())
                            headrooms.append(max(0, limit - used))
                        result["memory_files_read"] += 1
                except FileNotFoundError:
                    # A root cgroup, or a controller not enabled at this level,
                    # need not provide every resource control file.
                    pass
                except (OSError, ValueError, UnicodeError) as exc:
                    if len(result["errors"]) < 8:
                        result["errors"].append({"field": filename,
                                                 "errno": int(getattr(exc, "errno", 0) or 0)})
            if current == CGROUP_ROOT:
                result["hierarchy_complete"] = not result["errors"]
                break
            current = current.parent
        result["cpu_quota_state"] = ("limited" if cpu_limits else
                                     "unlimited_in_visible_hierarchy" if result["cpu_files_read"] else "unknown")
        if cpu_limits:
            result["cpu_quota_upper_bound_cores"] = round(min(cpu_limits), 8)
        if memory_limits:
            result["memory_limit_bytes"] = min(memory_limits)
        if headrooms:
            result["memory_headroom_bytes"] = min(headrooms)
        result["availability"] = "available" if result["hierarchy_complete"] else "partial"
    except (OSError, ValueError, UnicodeError) as exc:
        result.update(failure(exc))
    return result


def disk_probe(path):
    if not path:
        return {"availability": "path_not_supplied", "errno": 0}, None
    if len(path) > 4096 or "\0" in path:
        return {"availability": "invalid_path", "errno": errno.EINVAL}, None
    try:
        info = os.stat(path)
        if not stat.S_ISDIR(info.st_mode):
            return {"availability": "not_directory", "errno": errno.ENOTDIR}, None
        volume = os.statvfs(path)
        unit = volume.f_frsize or volume.f_bsize
        return ({"availability": "available", "total_bytes": volume.f_blocks * unit,
                 "available_bytes": max(0, volume.f_bavail) * unit,
                 "free_bytes": max(0, volume.f_bfree) * unit,
                 "filesystem_read_only": bool(volume.f_flag & os.ST_RDONLY),
                 "directory_write_access": os.access(path, os.W_OK, effective_ids=True),
                 "errno": 0}, info.st_dev)
    except (OSError, ValueError, UnicodeError) as exc:
        return failure(exc), None


def tools_probe():
    executables = {name: {"available_on_path": shutil.which(name) is not None}
                   for name in ("qemu-system-x86_64", "qemu-img", "swtpm", "swtpm_setup")}
    firmware_candidates = {
        "ovmf_code_4m_secure": "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
        "ovmf_vars_4m_ms": "/usr/share/OVMF/OVMF_VARS_4M.ms.fd",
        "ovmf_code_secure": "/usr/share/OVMF/OVMF_CODE.secboot.fd",
        "ovmf_vars_ms": "/usr/share/OVMF/OVMF_VARS.ms.fd",
        "edk2_ovmf_code_secure": "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "edk2_ovmf_vars_secure": "/usr/share/edk2/ovmf/OVMF_VARS.secboot.fd",
    }
    firmware = {}
    for label, path in firmware_candidates.items():
        try:
            info = os.stat(path)
            firmware[label] = {"present": True, "regular_file": stat.S_ISREG(info.st_mode),
                               "readable": os.access(path, os.R_OK, effective_ids=True),
                               "size_bytes": info.st_size, "errno": 0}
        except OSError as exc:
            firmware[label] = {"present": False, "errno": int(exc.errno or 0)}
    return {"executables": executables, "firmware_known_candidates": firmware,
            "executable_versions_executed": False, "firmware_contents_validated": False,
            "secure_boot_verified_in_guest": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kvm-only", action="store_true")
    args = parser.parse_args()
    report = {"schema": SCHEMA, "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "kind": "read_only_measurement", "scope": "kvm_only" if args.kvm_only else "host",
              "privileged_process": os.geteuid() == 0, "windows_boot_tested": False,
              "kvm": kvm_probe()}
    if not args.kvm_only:
        machine = platform.machine().lower()
        report["architecture"] = machine if machine in ("x86_64", "aarch64", "i386", "i686") else "other"
        report["cpu"] = cpu_probe()
        report["memory"] = memory_probe()
        report["cgroup"] = cgroup_probe()
        temp, temp_device = disk_probe(os.environ.get("RUNNER_TEMP"))
        workspace, workspace_device = disk_probe(os.environ.get("GITHUB_WORKSPACE"))
        report["storage"] = {"runner_temp": temp, "workspace": workspace,
                             "same_filesystem": (temp_device == workspace_device
                                                 if temp_device is not None and workspace_device is not None else None)}
        report["tools"] = tools_probe()
    encoded = json.dumps(report, separators=(",", ":"), allow_nan=False)
    if len(encoded) > 32768:
        raise RuntimeError("output bound exceeded")
    print(encoded)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"schema": SCHEMA, "kind": "collector_failed",
                          "errno": int(getattr(exc, "errno", 0) or 0)}, separators=(",", ":")))
        raise SystemExit(1)
