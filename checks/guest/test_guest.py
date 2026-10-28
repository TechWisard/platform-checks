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
import failure_diagnostics as diagnostics


class HostContractTests(unittest.TestCase):
    nonce = "1A" * 24

    def hello(self, nonce=None):
        return b"\nGUEST_HELLO_V1 " + (nonce or self.nonce).encode("ascii") + b"\n"

    def frame(self, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        return b"GUEST_RESULT_V1 " + str(len(body)).encode() + b" " + hashlib.sha256(body).hexdigest().upper().encode() + b"\n" + body + b"\n"

    def value(self):
        return {"schema": "windows-guest-session-result/v1", "nonce": self.nonce, "status": "failed"}

    def test_fragmented_frame_and_phase(self):
        reader = guest.SerialReader(self.nonce)
        data = self.hello() + b"GUEST_PHASE_V1 supervisor_started\n" + self.frame(self.value())
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
                    guest.SerialReader(self.nonce).feed(self.hello() + data)

    def test_no_phase_or_serial_startup_counts_as_success(self):
        reader = guest.SerialReader(self.nonce)
        reader.feed(self.hello() + b"GUEST_PHASE_V1 supervisor_started\n")
        self.assertIsNone(reader.result)
        with self.assertRaises(guest.Failure):
            reader.feed(b"GUEST_PHASE_V1 supervisor_started\n" * 32)

    def test_ansi_no_newline_and_split_hello(self):
        reader = guest.SerialReader(self.nonce)
        noise = b"\x1b[2J\x1b[?25lBdsDxe: UEFI boot output without a final newline"
        data = noise + self.hello() + b"GUEST_PHASE_V1 supervisor_started\n" + self.frame(self.value())
        phases = []
        for byte in data:
            phases.extend(reader.feed(bytes([byte])))
        self.assertTrue(reader.hello_verified)
        self.assertEqual(reader.result, self.value())
        self.assertEqual(phases, ["supervisor_started"])
        observation = reader.startup_observation()
        self.assertEqual(observation["pre_hello_bytes"], len(noise))
        self.assertEqual(observation["marker_categories"], ["ansi_escape", "bdsdxe_marker", "uefi_marker"])
        self.assertFalse(guest.successful_result(reader.result))

    def test_noise_and_unbound_phase_are_never_supervisor_proof(self):
        reader = guest.SerialReader(self.nonce)
        noise = b"boot text\x1b[0m\nGUEST_PHASE_V1 supervisor_started\n"
        self.assertEqual(reader.feed(noise), [])
        self.assertFalse(reader.hello_verified)
        self.assertIsNone(reader.result)
        self.assertEqual(reader.startup_observation()["pre_hello_bytes"], len(noise))
        self.assertEqual(reader.feed(self.hello()), [])
        self.assertTrue(reader.hello_verified)
        self.assertIsNone(reader.result)

    def test_wrong_nonce_hello_and_oversize_hello_rejected(self):
        for hello in (self.hello("2B" * 24), b"\nGUEST_HELLO_V1 " + b"A" * 49):
            with self.subTest(size=len(hello)):
                reader = guest.SerialReader(self.nonce)
                with self.assertRaises(guest.Failure):
                    reader.feed(hello)
                self.assertFalse(reader.hello_verified)
                self.assertIsNone(reader.result)

    def test_preamble_byte_and_time_limits(self):
        reader = guest.SerialReader(self.nonce)
        oversized = b"x" * (reader.MAX_NOISE_BYTES + len(reader.HELLO_PREFIX))
        with self.assertRaises(guest.Failure) as context:
            reader.feed(oversized)
        self.assertEqual(context.exception.stage, "serial_noise_limit")
        self.assertEqual(reader.startup_observation()["pre_hello_bytes"], len(oversized))
        reader = guest.SerialReader(self.nonce)
        reader.noise_started -= reader.MAX_PRE_HELLO_SECONDS + 1
        with self.assertRaises(guest.Failure) as context:
            reader.feed(b"")
        self.assertEqual(context.exception.stage, "serial_hello_timeout")
        reader = guest.SerialReader(self.nonce)
        reader.feed(self.hello())
        with self.assertRaises(guest.Failure) as context:
            reader.feed(b"x" * (2 * 1024 * 1024 + 1))
        self.assertEqual(context.exception.stage, "serial_resource_limit")

    def test_after_hello_firmware_text_and_second_hello_are_errors(self):
        for unexpected in (b"\x1b[0mUEFI unexpected output\n", self.hello()):
            reader = guest.SerialReader(self.nonce)
            reader.feed(self.hello())
            with self.assertRaises(guest.Failure) as context:
                reader.feed(unexpected)
            self.assertEqual(context.exception.stage, "unexpected_serial_frame")

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
                     power_request={"acquired": True, "cleanup_verified": True},
                     activation_observation={"candidate_count": 1, "license_status": 1, "step": 7},
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
        for key in ("acquired", "cleanup_verified"):
            changed = copy.deepcopy(value); changed["power_request"][key] = False
            self.assertFalse(guest.successful_result(changed), key)
        for key, replacement in (("candidate_count", 0), ("candidate_count", 2), ("candidate_count", True),
                                 ("license_status", 2), ("license_status", True), ("step", 6)):
            changed = copy.deepcopy(value); changed["activation_observation"][key] = replacement
            self.assertFalse(guest.successful_result(changed), key)

    def activation(self, iteration, step, code=0, count=-1, status=-1, reason=-1):
        return f"GUEST_ACTIVATION_V1 {iteration} {step} {code} {count} {status} {reason}\n".encode()

    def test_activation_fragments_are_bounded_diagnostic_not_success(self):
        reader = guest.SerialReader(self.nonce)
        data = self.hello() + b"".join(self.activation(1, step) for step in range(7)) + self.activation(1, 7, count=1, status=1, reason=0)
        for start in range(0, len(data), 3):
            self.assertEqual(reader.feed(data[start:start + 3]), [])
        observations = reader.take_activation_observations()
        self.assertEqual(len(observations), 8)
        self.assertEqual(observations[-1]["license_status"], 1)
        self.assertEqual(reader.take_activation_observations(), [])
        self.assertEqual(reader.phases, 0)
        self.assertIsNone(reader.result)
        self.assertEqual(reader.feed(self.frame(self.value())), [])
        self.assertFalse(guest.successful_result(reader.result))

    def test_activation_order_ranges_and_private_text_rejected(self):
        bad = [self.activation(2, 0), self.activation(1, 2), self.activation(19, 0), self.activation(1, 0, 2**31),
               self.activation(1, 0, count=1), b"GUEST_ACTIVATION_V1 credential-secret\n"]
        for line in bad:
            with self.subTest(line_length=len(line)):
                with self.assertRaises(guest.Failure):
                    guest.SerialReader(self.nonce).feed(self.hello() + line)
        prefix = self.hello() + b"".join(self.activation(1, step) for step in range(7))
        for invalid in (self.activation(1, 7, count=1, status=-1, reason=0),
                        self.activation(1, 7, count=2, status=1, reason=0),
                        self.activation(1, 7, count=1, status=1, reason=2**32)):
            with self.assertRaises(guest.Failure):
                guest.SerialReader(self.nonce).feed(prefix + invalid)

    def test_activation_error_is_terminal_and_iterations_capped(self):
        reader = guest.SerialReader(self.nonce)
        reader.feed(self.hello() + self.activation(1, 0) + self.activation(1, 1) + self.activation(1, 8, -2147023436))
        self.assertEqual(reader.take_activation_observations()[-1]["step"], 8)
        with self.assertRaises(guest.Failure):
            reader.feed(self.activation(2, 0))
        reader = guest.SerialReader(self.nonce)
        reader.feed(self.hello())
        for iteration in range(1, 19):
            data = b"".join(self.activation(iteration, step) for step in range(7)) + self.activation(iteration, 7, count=0)
            reader.feed(data)
        self.assertEqual(reader.activation_count, 144)
        self.assertIsNone(reader.result)
        with self.assertRaises(guest.Failure):
            reader.feed(self.activation(19, 0))

    def test_qmp_state_whitelist_never_leaks_unknown_state(self):
        class Qmp:
            def __init__(self, value): self.value = value
            def call(self, name):
                self.assertion = name == "query-status"
                return self.value
        for state in ("running", "paused", "suspended", "guest-panicked", "io-error"):
            value = diagnostics.query_state(Qmp({"running": state == "running", "status": state, "extra": "private-text"}))
            self.assertEqual(value["status"], state)
            self.assertNotIn("private-text", json.dumps(value))
        for value in ({"running": 1, "status": "running"}, {"running": False, "status": "private-text"}, None):
            self.assertEqual(diagnostics.query_state(Qmp(value)), {"query_succeeded": False})

    def tsv(self, words, confidence=90):
        header = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n"
        return (header + "".join(f"5\t1\t1\t1\t1\t{number}\t0\t0\t10\t10\t{confidence}\t{word}\n"
                                for number, word in enumerate(words, 1))).encode()

    def test_ocr_only_fixed_labels_and_confidence_never_raw_words(self):
        words = "PrivateUser credential-secret Your device ran into a problem Stop code".split()
        result = diagnostics.classify_tsv(self.tsv(words))
        self.assertEqual(result["fixed_label_ids"], ["windows_problem_message", "windows_stop_code_label"])
        self.assertNotIn("PrivateUser", json.dumps(result)); self.assertNotIn("credential-secret", json.dumps(result))
        self.assertEqual(diagnostics.classify_tsv(self.tsv(words, 20))["fixed_label_ids"], [])
        self.assertEqual(diagnostics.classify_tsv(self.tsv(["arbitrary", "desktop", "text"]))["fixed_label_ids"], [])
        for invalid in (b"x" * 65537, self.tsv(["x"], float("nan")), b"arbitrary raw OCR text"):
            with self.assertRaises(ValueError): diagnostics.classify_tsv(invalid)

    def test_failure_screen_is_own_temporary_and_removed_after_ocr_failure(self):
        class Qmp:
            def call(self, name, arguments=None):
                if name == "query-status": return {"running": False, "status": "suspended"}
                self.path = Path(arguments["filename"])
                self.path.write_bytes(b"P6\n2 2\n255\n" + b"\0" * 12)
                return {}
        def failed_ocr(*args, **kwargs): raise ValueError("raw credential-secret")
        with tempfile.TemporaryDirectory() as directory:
            qmp = Qmp()
            result = diagnostics.observe_failure(qmp, Path(directory), guest.Deadline(), failed_ocr)
            self.assertTrue(result["diagnostic_only"])
            self.assertTrue(result["screen_capture_succeeded"])
            self.assertFalse(result["ocr_succeeded"])
            self.assertTrue(result["temporary_image_removed"])
            self.assertFalse(qmp.path.exists())
            self.assertNotIn("credential-secret", json.dumps(result))

    def test_ppm_pixel_and_file_bounds_before_decoder(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.ppm"
            path.write_bytes(b"P6\n2 2\n255\n" + b"\0" * 12)
            self.assertEqual(diagnostics.ppm_dimensions(path), (2, 2))
            for data in (b"P6\n9999 9999\n255\n", b"P6\n2 2\n255\n" + b"\0" * 11, b"not-an-image"):
                path.write_bytes(data)
                with self.assertRaises(ValueError): diagnostics.ppm_dimensions(path)

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
