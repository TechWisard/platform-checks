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
                     activation_audit=self.audit(),
                     work_directory_cleanup=self.work_cleanup(),
                     test=self.session_contract())
        self.assertTrue(guest.successful_result(value))
        for key in gates:
            changed = copy.deepcopy(value); changed[key] = False
            self.assertFalse(guest.successful_result(changed), key)
        for key in ("different_account_verified", "frame_challenge_verified", "window_input_verified",
                    "window_input_cleanup_verified", "window_child_received_expected_text", "window_child_received_expected_button_sequence"):
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
        for replacement in (None, [], {}, True, [self.work_cleanup()[0]]):
            changed = copy.deepcopy(value); changed["work_directory_cleanup"] = replacement
            self.assertFalse(guest.successful_result(changed))

    def work_cleanup(self):
        return [dict(area_id=area, owned=True, present_before=True, removal_verified=True,
                     error_stage=0, error_kind=None, error_hresult=None) for area in (1, 2)]

    def test_work_cleanup_projection_and_acceptance_are_strict(self):
        self.assertEqual(guest.work_directory_cleanup_projection(self.work_cleanup()), self.work_cleanup())
        self.assertTrue(guest.work_directory_cleanup_verified(self.work_cleanup()))
        self.assertEqual(guest.work_directory_cleanup_projection([]), [])
        self.assertFalse(guest.work_directory_cleanup_verified([]))
        for key, replacement in (("area_id", True), ("area_id", 2), ("owned", 1), ("present_before", "true"),
                                 ("removal_verified", 1), ("error_stage", True), ("error_kind", "IOException"),
                                 ("error_hresult", "private_path"), ("error_hresult", 2**31), ("extra", "private_path")):
            changed = self.work_cleanup(); changed[0][key] = replacement
            with self.assertRaises(guest.Failure): guest.work_directory_cleanup_projection(changed)
            self.assertFalse(guest.work_directory_cleanup_verified(changed))
        for key in self.work_cleanup()[0]:
            changed = self.work_cleanup(); del changed[0][key]
            with self.assertRaises(guest.Failure): guest.work_directory_cleanup_projection(changed)
        locked = self.work_cleanup()
        locked[0].update(removal_verified=False, error_stage=2, error_kind=2, error_hresult=-2147024864)
        self.assertEqual(guest.work_directory_cleanup_projection(locked), locked)
        self.assertFalse(guest.work_directory_cleanup_verified(locked))
        for key, replacement in (("owned", False), ("present_before", False), ("error_stage", 0), ("error_kind", None),
                                 ("error_hresult", None), ("removal_verified", True)):
            changed = copy.deepcopy(locked); changed[0][key] = replacement
            with self.assertRaises(guest.Failure): guest.work_directory_cleanup_projection(changed)
        unowned = self.work_cleanup(); unowned[0].update(owned=False, present_before=None)
        self.assertEqual(guest.work_directory_cleanup_projection(unowned), unowned)
        self.assertFalse(guest.work_directory_cleanup_verified(unowned))

    def session_contract(self):
        # A synthetic own-window receipt only; no physical or direct input is
        # represented by this data or inferred from a subprocess exit code.
        value = dict(schema="session-contract-experiment/v1", status="different_account_child_frame_and_window_input_verified")
        value.update({key: True for key in (
            "window_input_requested", "window_input_verified", "window_input_cleanup_verified",
            "window_child_received_expected_text", "window_child_received_expected_button_sequence",
            "frame_challenge_verified", "different_account_verified", "parent_and_child_active",
            "child_matches_created_account_sid", "witness_in_expected_session", "witness_identity_matches",
            "alternate_test_account_requested", "test_account_created", "test_account_non_administrator_verified", "test_credentials_applied",
            "child_removed", "enable_state_restored", "task_removed", "task_instances_stopped", "test_account_removed",
            "witness_sandbox_removed", "parent_still_active_after_cleanup", "console_session_unchanged",
            "child_search_preparation_cleanup_verified")})
        value.update({key: False for key in (
            "direct_input_requested", "direct_input_channel_verified", "physical_input_isolation_verified",
            "native_multiseat_verified", "same_user_sid", "witness_administrator_group_present", "child_search_preparation_requested")})
        return value

    def test_window_input_requires_exact_mode_receipts_and_each_boolean(self):
        value = self.session_contract()
        self.assertTrue(guest.successful_session_contract(value))
        for key, expected in value.items():
            if type(expected) is not bool:
                continue
            for replacement in (not expected, None, str(expected).lower(), int(expected), [], {}):
                changed = copy.deepcopy(value); changed[key] = replacement
                self.assertFalse(guest.successful_session_contract(changed), (key, replacement))
            changed = copy.deepcopy(value); del changed[key]
            self.assertFalse(guest.successful_session_contract(changed), (key, "missing"))
        for key in ("schema", "status"):
            for replacement in (None, True, [], {}, value[key].upper(), "unrecognized"):
                changed = copy.deepcopy(value); changed[key] = replacement
                self.assertFalse(guest.successful_session_contract(changed), (key, replacement))
        for replacement in (None, [], "verified", True):
            self.assertFalse(guest.successful_session_contract(replacement))

    def test_old_direct_input_or_frame_only_receipts_cannot_pass_window_mode(self):
        value = self.session_contract()
        for status in ("different_account_child_frame_and_input_verified", "different_account_child_and_frame_verified"):
            changed = copy.deepcopy(value); changed["status"] = status
            self.assertFalse(guest.successful_session_contract(changed))
        changed = copy.deepcopy(value)
        changed.update(direct_input_requested=True, direct_input_channel_verified=True,
                       child_received_expected_text=True, child_received_expected_button_sequence=True,
                       window_input_requested=False, window_input_verified=False,
                       window_child_received_expected_text=False, window_child_received_expected_button_sequence=False)
        self.assertFalse(guest.successful_session_contract(changed))

    def audit(self):
        snapshot = dict(candidate_count=1, license_status=1, license_status_reason=0, grace_period_remaining=0,
                        evaluation_end_utc=None, trusted_time_utc=None, guest_utc=1793232000, evaluation_expired=None)
        return dict(before=snapshot, after=copy.deepcopy(snapshot), network=None, attempt_count=0,
                    method_process_started=False, method_process_completed=False, method_process_exit_code=None,
                    method_reply=None, same_product_verified=True, licensed_status_confirmed=True)

    def method_audit(self):
        audit = self.audit()
        audit["before"]["license_status"] = 5
        audit["before"]["license_status_reason"] = 3221549065
        audit.update(attempt_count=1, method_process_started=True, method_process_completed=True, method_process_exit_code=0,
                     network=[dict(endpoint_id=i, dns_succeeded=True, tcp_succeeded=True, tls_succeeded=True, error_hresult=None)
                              for i in (1, 2)],
                     method_reply=dict(invocation_started=True, invocation_returned=True, return_value=0,
                                       error_hresult=None, guard_code=0, same_product_verified=True,
                                       result_shape=3, result_error_hresult=None))
        return audit

    def test_activation_audit_requires_fresh_license_not_method_return(self):
        audit = self.method_audit()
        self.assertTrue(guest.licensed_audit(audit))
        audit["after"]["license_status"] = 5
        self.assertFalse(guest.licensed_audit(audit))
        for key in ("same_product_verified", "licensed_status_confirmed"):
            changed = self.method_audit(); changed[key] = False
            self.assertFalse(guest.licensed_audit(changed))
        changed = self.method_audit(); changed["method_reply"]["same_product_verified"] = False
        self.assertFalse(guest.licensed_audit(changed))
        # A provider error can coexist with an independently observed Licensed
        # state; a success method return cannot create that observation.
        changed = self.method_audit(); changed["method_reply"]["return_value"] = 3221549065
        self.assertTrue(guest.licensed_audit(changed))

    def test_activation_audit_unknown_completion_never_passes(self):
        for completed, reply in ((False, None), (True, None), (True, dict(invocation_started=True,
                invocation_returned=False, return_value=None, error_hresult=-2147023436, guard_code=0, same_product_verified=True,
                result_shape=0, result_error_hresult=None))):
            changed = self.method_audit()
            changed.update(method_process_completed=completed, method_process_exit_code=0 if completed else None, method_reply=reply)
            self.assertFalse(guest.licensed_audit(changed))
        changed = self.method_audit(); changed["attempt_count"] = 2
        self.assertFalse(guest.licensed_audit(changed))

    def test_returned_unknown_output_needs_actual_fresh_same_product_license(self):
        for shape in (1, 2, 4, 5, 6):
            with self.subTest(shape=shape):
                audit = self.method_audit()
                audit["method_reply"].update(return_value=None, result_shape=shape,
                                             result_error_hresult=-2146233087 if shape == 6 else None)
                self.assertEqual(guest.activation_audit_projection(audit), audit)
                self.assertTrue(guest.licensed_audit(audit))
                self.assertIsNone(audit["method_reply"]["return_value"])
                for key in ("same_product_verified", "licensed_status_confirmed"):
                    broken = copy.deepcopy(audit); broken[key] = False
                    self.assertFalse(guest.licensed_audit(broken))
                for after in (None, audit["before"], audit["after"] | {"license_status": 0},
                              audit["after"] | {"license_status": 5}):
                    broken = copy.deepcopy(audit); broken["after"] = after
                    self.assertFalse(guest.licensed_audit(broken))
                broken = copy.deepcopy(audit)
                broken["method_reply"]["same_product_verified"] = False
                self.assertFalse(guest.licensed_audit(broken))

    def test_method_result_shape_and_error_domains_are_not_interchangeable(self):
        for fields in (
            {"result_shape": 0}, {"result_shape": 1}, {"result_shape": 2}, {"result_shape": 6},
            {"result_shape": 7}, {"result_shape": True}, {"result_shape": "3"},
            {"result_error_hresult": -1}, {"result_error_hresult": True},
            {"result_error_hresult": 2**31}, {"error_hresult": -2146233087},
            {"return_value": None}, {"return_value": False},
            {"invocation_returned": False, "return_value": None, "error_hresult": -1},
        ):
            with self.subTest(fields=fields):
                audit = self.method_audit(); audit["method_reply"].update(fields)
                self.assertFalse(guest.licensed_audit(audit))
                with self.assertRaises(guest.Failure): guest.activation_audit_projection(audit)
        # An unknown native completion remains unknown even if a later status
        # claims Licensed. A local post-return projection error is different.
        audit = self.method_audit()
        audit["method_reply"].update(invocation_returned=False, return_value=None,
                                     result_shape=0, error_hresult=-2147023436)
        self.assertEqual(guest.activation_audit_projection(audit), audit)
        self.assertFalse(guest.licensed_audit(audit))

    def test_activation_audit_expiry_unknowns_and_clock_types(self):
        self.assertTrue(guest.licensed_audit(self.audit()))
        for end, trusted in ((1793231999, None), (1793232001, 1793232002)):
            changed = self.method_audit()
            changed["after"].update(evaluation_end_utc=end, trusted_time_utc=trusted, evaluation_expired=True)
            self.assertFalse(guest.licensed_audit(changed))
        for key, replacement in (("guest_utc", None), ("guest_utc", False), ("evaluation_end_utc", 0),
                                 ("trusted_time_utc", "private-text"), ("license_status", True), ("candidate_count", True)):
            changed = self.method_audit(); changed["after"][key] = replacement
            with self.assertRaises(guest.Failure): guest.activation_audit_projection(changed)
        changed = self.method_audit(); changed["after"].update(evaluation_end_utc=1793231999, evaluation_expired=False)
        self.assertFalse(guest.licensed_audit(changed))

    def test_activation_audit_projection_rejects_unknown_text_and_keys(self):
        audit = self.method_audit()
        self.assertEqual(guest.activation_audit_projection(audit), audit)
        for path in ((), ("after",), ("method_reply",), ("network", 0)):
            changed = self.method_audit(); node = changed
            for key in path: node = node[key]
            node["private_text"] = "credential-secret"
            with self.assertRaises(guest.Failure): guest.activation_audit_projection(changed)
        for key in ("method_process_started", "method_process_completed", "same_product_verified", "licensed_status_confirmed"):
            changed = self.method_audit(); changed[key] = 1
            self.assertFalse(guest.licensed_audit(changed))

    def test_activation_network_is_diagnostic_and_strictly_typed(self):
        changed = self.method_audit()
        changed["network"] = [dict(endpoint_id=i, dns_succeeded=False, tcp_succeeded=False, tls_succeeded=False,
                                   error_hresult=-1) for i in (1, 2)]
        self.assertTrue(guest.licensed_audit(changed))
        for key, replacement in (("endpoint_id", True), ("dns_succeeded", 1), ("error_hresult", "private")):
            broken = self.method_audit(); broken["network"][0][key] = replacement
            self.assertFalse(guest.licensed_audit(broken))
        broken = self.method_audit(); broken["network"][0]["dns_succeeded"] = False
        self.assertFalse(guest.licensed_audit(broken))
        broken = self.method_audit(); broken["network"].append(broken["network"][0])
        self.assertFalse(guest.licensed_audit(broken))

    def test_activation_preinvoke_guards_and_already_licensed(self):
        changed = self.method_audit()
        changed["method_reply"].update(invocation_started=False, invocation_returned=False, return_value=None, guard_code=1, result_shape=0)
        self.assertTrue(guest.licensed_audit(changed))
        changed["method_reply"]["guard_code"] = 2
        self.assertFalse(guest.licensed_audit(changed))
        changed["method_reply"].update(guard_code=3, same_product_verified=False)
        self.assertFalse(guest.licensed_audit(changed))
        changed["method_reply"].update(guard_code=4, error_hresult=-1)
        self.assertFalse(guest.licensed_audit(changed))
        for changed in (None, True, {}, self.method_audit() | {"attempt_count": True}):
            self.assertFalse(guest.licensed_audit(changed))

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
