"""Local tests of framing/resource bounds only; these never run a Windows VM."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET

import run_guest as guest


class HostContractTests(unittest.TestCase):
    nonce = "1A" * 24

    def frame(self, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        return b"GUEST_RESULT_V1 " + str(len(body)).encode() + b" " + hashlib.sha256(body).hexdigest().upper().encode() + b"\n" + body + b"\n"

    def value(self):
        return {"schema": "windows-guest-session-result/v1", "nonce": self.nonce, "status": "failed"}

    def test_fragmented_frame_and_phase(self):
        reader = guest.SerialReader(self.nonce)
        data = b"GUEST_PHASE_V1 supervisor_started\n" + self.frame(self.value())
        phases = []
        for start in range(0, len(data), 7):
            phases.extend(reader.feed(data[start:start + 7]))
        self.assertEqual(phases, ["supervisor_started"])
        self.assertEqual(reader.result, self.value())
        self.assertFalse(guest.successful_result(reader.result))

    def test_binding_digest_trailing_and_size_rejected(self):
        cases = []
        wrong = self.value(); wrong["nonce"] = "wrong"
        cases.append(self.frame(wrong))
        damaged = self.frame(self.value()).replace(b'"failed"', b'"broken"')
        cases.append(damaged)
        cases.append(self.frame(self.value()) + b"unexpected\n")
        cases.append(b"GUEST_RESULT_V1 99999 " + b"0" * 64 + b"\n")
        cases.append(b"x" * 257)
        for data in cases:
            with self.subTest(length=len(data)):
                with self.assertRaises(guest.Failure):
                    guest.SerialReader(self.nonce).feed(data)

    def test_no_phase_or_serial_startup_counts_as_success(self):
        reader = guest.SerialReader(self.nonce)
        reader.feed(b"GUEST_PHASE_V1 supervisor_started\n")
        self.assertIsNone(reader.result)
        with self.assertRaises(guest.Failure):
            reader.feed(b"GUEST_PHASE_V1 supervisor_started\n" * 32)

    def test_success_requires_every_actual_gate(self):
        # Synthetic unit input exercises the predicate. It is never emitted as
        # guest evidence and never substitutes for an actual serial result.
        value = self.value()
        gates = ("guest_identity_verified", "elevated", "interactive_console_verified", "secure_boot_verified", "tpm2_verified",
                 "fixture_presentation_verified", "activation_licensed_observed", "offline_runtime_verified", "harness_compiled",
                 "autologon_disabled", "setup_media_was_readable", "setup_media_unavailable_verified",
                 "cached_answer_files_absent_verified", "harness_cleanup_verified", "guest_work_directories_removed")
        value.update({name: True for name in gates})
        value.update(status="verified", test_exit_code=0, cleanup_unverified=False,
                     physical_input_isolation_verified=False, native_multiseat_verified=False,
                     test={"different_account_verified": True, "frame_challenge_verified": True, "direct_input_channel_verified": True})
        self.assertTrue(guest.successful_result(value))
        for key in gates:
            changed = copy.deepcopy(value); changed[key] = False
            self.assertFalse(guest.successful_result(changed), key)
        for key in ("different_account_verified", "frame_challenge_verified", "direct_input_channel_verified"):
            changed = copy.deepcopy(value); changed["test"][key] = False
            self.assertFalse(guest.successful_result(changed), key)
        for key, replacement in (("test_exit_code", False), ("test_exit_code", 1), ("cleanup_unverified", True),
                                 ("physical_input_isolation_verified", True), ("native_multiseat_verified", True)):
            changed = copy.deepcopy(value); changed[key] = replacement
            self.assertFalse(guest.successful_result(changed), key)

    def test_unattend_setup_boundary_and_command_length(self):
        root = ET.fromstring(guest.unattend("scgatest001", "SyntheticTestPassword1!", "SCG-UNIT", 1))
        ns = {"u": guest.UNATTEND}
        commands = root.findall(".//u:FirstLogonCommands/u:SynchronousCommand/u:CommandLine", ns)
        self.assertEqual(len(commands), 1)
        self.assertLessEqual(len(commands[0].text), 1024)
        self.assertIn('-Command "& { ', commands[0].text)
        self.assertIn("Start-Process", commands[0].text)
        self.assertNotIn("-Wait", commands[0].text)
        self.assertNotIn("ExecutionPolicy", commands[0].text)
        self.assertNotIn("SyntheticTestPassword1!", commands[0].text)
        descriptions = root.findall(".//u:FirstLogonCommands/u:SynchronousCommand/u:Description", ns)
        self.assertEqual(descriptions[0].text, "Owned session fixture " + "0" * 48)
        oobe = root.find("u:settings[@pass='oobeSystem']", ns)
        locale = oobe.find("u:component[@name='Microsoft-Windows-International-Core']", ns)
        self.assertEqual(len(locale), 4)
        policies = root.findall("u:settings[@pass='specialize']/u:component[@name='Microsoft-Windows-Deployment']/u:RunSynchronous/u:RunSynchronousCommand/u:Path", ns)
        self.assertEqual(len(policies), 2)
        self.assertTrue(any("EnableFirstLogonAnimation /t REG_DWORD /d 0" in item.text for item in policies))
        self.assertTrue(any("DisablePrivacyExperience /t REG_DWORD /d 1" in item.text for item in policies))

    def test_bounded_command_normal_and_single_line_overflow(self):
        normal = guest.command([sys.executable, "-c", "print('local-test')"], guest.Deadline(), 5)
        self.assertEqual(normal, b"local-test\n")
        with self.assertRaises(guest.Failure) as context:
            guest.command([sys.executable, "-c", "import os; os.write(1,b'x'*8192)"], guest.Deadline(), 5, maximum_output_bytes=1024)
        self.assertEqual(context.exception.stage, "tool_stdout_limit")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bounded.bin"
            with self.assertRaises(guest.Failure):
                guest.command([sys.executable, "-c", "import os; os.write(1,b'x'*8192)"], guest.Deadline(), 5,
                              output, maximum_output_bytes=1024)
            self.assertLessEqual(output.stat().st_size, 1024)

    def test_owned_command_timeout_is_bounded(self):
        started = time.monotonic()
        with self.assertRaises(guest.Failure) as context:
            guest.command([sys.executable, "-c", "import time; time.sleep(60)"], guest.Deadline(), 0.25)
        self.assertEqual(context.exception.stage, "tool_timeout")
        self.assertLess(time.monotonic() - started, 6)

    def test_diagnostic_emits_only_fixed_category(self):
        text = b"private/path/credential-secret: Permission denied"
        self.assertEqual(guest.diagnostic_category(text), "permission_denied")
        self.assertEqual(guest.diagnostic_category(b"private/path/credential-secret"), "unclassified")

    def test_setup_detach_refuses_wrong_medium_before_mutation(self):
        class Observed:
            calls = []
            def call(self, name, arguments=None):
                self.calls.append(name)
                if name == "query-status": return {"running": False}
                if name == "query-block":
                    return [{"device": "answerbackend", "qdev": "setupcd", "removable": True,
                             "inserted": {"file": "/not-the-owned-setup.iso", "ro": True}}]
                return {}
        qmp = Observed()
        with tempfile.TemporaryDirectory() as directory:
            setup = Path(directory) / "setup.iso"; setup.write_bytes(b"unit-only")
            with self.assertRaises(guest.Failure) as context:
                guest.remove_setup_medium(qmp, setup)
            self.assertEqual(context.exception.stage, "setup_medium_ownership_not_verified")
            self.assertTrue(setup.exists())
            self.assertNotIn("blockdev-open-tray", qmp.calls)
            self.assertNotIn("blockdev-remove-medium", qmp.calls)
            self.assertNotIn("cont", qmp.calls)

    def test_setup_detach_waits_for_actual_no_medium_before_resume(self):
        class Observed:
            def __init__(self, path):
                self.entry = {"device": "answerbackend", "qdev": "setupcd", "removable": True, "tray_open": False,
                              "inserted": {"file": str(path), "ro": True}}
                self.path, self.running, self.calls = path, True, []
            def call(self, name, arguments=None):
                self.calls.append(name)
                if name == "stop": self.running = False
                elif name == "query-status": return {"running": self.running}
                elif name == "query-block": return [copy.deepcopy(self.entry)]
                elif name == "blockdev-open-tray":
                    assert arguments == {"id": "setupcd", "force": False}
                    self.entry["tray_open"] = True
                elif name == "blockdev-remove-medium":
                    assert arguments == {"id": "setupcd"}
                    del self.entry["inserted"]
                elif name == "cont":
                    assert "inserted" not in self.entry and not self.path.exists()
                    self.running = True
                return {}
        with tempfile.TemporaryDirectory() as directory:
            setup = Path(directory) / "setup.iso"; setup.write_bytes(b"unit-only")
            qmp = Observed(setup)
            with contextlib.redirect_stdout(io.StringIO()):
                guest.remove_setup_medium(qmp, setup)
            self.assertFalse(setup.exists())
            self.assertTrue(qmp.running)
            self.assertEqual(qmp.calls.count("blockdev-remove-medium"), 1)


if __name__ == "__main__":
    unittest.main()
