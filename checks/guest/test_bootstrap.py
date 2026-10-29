import json
import base64
import unittest

import bootstrap_diagnostics as diagnostic
import run_guest as guest


class BootstrapContracts(unittest.TestCase):
    @staticmethod
    def capture():
        return diagnostic.BootstrapCapture()

    def test_chunk_boundaries_and_numeric_failure_are_preserved(self):
        data = b"GUEST_BOOTSTRAP_V1 2 1\r\nGUEST_BOOTSTRAP_V1 17 -2147024891\nGUEST_BOOTSTRAP_V1 18 5\n"
        expected = [{"stage_id": 2, "code": 1}, {"stage_id": 17, "code": -2147024891},
                    {"stage_id": 18, "code": 5}]
        for split in range(len(data) + 1):
            reader = self.capture()
            reader.feed(data[:split])
            reader.feed(data[split:])
            self.assertEqual(reader.records, expected)
            self.assertEqual(reader.rejected, 0)

    def test_unknown_and_sensitive_text_never_become_observations(self):
        reader = self.capture()
        reader.feed(b"account-private password-private path-private\n"
                    b'{"schema":"private","nonce":"private-token"}\n'
                    b"GUEST_BOOTSTRAP_V1 99 0\nGUEST_BOOTSTRAP_V1 2 27\n"
                    b"GUEST_BOOTSTRAP_V1 3 2\nGUEST_BOOTSTRAP_V1 10 7\n"
                    b"GUEST_BOOTSTRAP_V1 17 -2147483649\nGUEST_BOOTSTRAP_V1 17 2147483648\n"
                    b"GUEST_BOOTSTRAP_V1 11 64\n")
        self.assertEqual(reader.records, [{"stage_id": 11, "code": 64}])
        self.assertEqual(reader.rejected, 8)
        rendered = json.dumps(reader.summary())
        self.assertNotIn("private", rendered)
        self.assertFalse(reader.summary()["emitter_identity_verified"])

    def test_record_and_total_byte_limits(self):
        reader = self.capture()
        reader.feed(b"GUEST_BOOTSTRAP_V1 1 0\n" * 17)
        self.assertEqual(len(reader.records), 16)
        self.assertTrue(reader.summary()["record_limit_reached"])
        reader = self.capture()
        reader.feed(b"X" * (reader.MAX_BYTES + 1))
        self.assertTrue(reader.summary()["byte_limit_reached"])
        self.assertLessEqual(len(reader.buffer), reader.MAX_LINE)
        self.assertEqual(reader.records, [])

    def test_overlong_split_line_resynchronizes_only_after_newline(self):
        reader = self.capture()
        reader.feed(b"X" * 129)
        reader.feed(b"GUEST_BOOTSTRAP_V1 1 0\nGUEST_BOOTSTRAP_V1 4 0\n")
        self.assertEqual(reader.rejected, 1)
        self.assertEqual(reader.records, [{"stage_id": 4, "code": 0}])

    def test_terminal_ring_read_is_bounded_base64_and_not_replayed(self):
        class Qmp:
            calls = []
            def call(self, command, arguments):
                self.calls.append((command, arguments))
                return base64.b64encode(b"GUEST_BOOTSTRAP_V1 0 0\n").decode("ascii")
        qmp, reader = Qmp(), self.capture()
        self.assertEqual(reader.observe(qmp), [{"stage_id": 0, "code": 0}])
        self.assertEqual(reader.observe(qmp), [])
        self.assertEqual(qmp.calls, [("ringbuf-read", {"device": "bootstrap0", "size": 4096, "format": "base64"})])
        self.assertFalse(reader.summary()["incomplete_line"])

    def test_read_failure_has_only_numeric_error(self):
        class Qmp:
            def call(self, command, arguments):
                raise RuntimeError("private-path private-error")
        for qmp in (Qmp(), None):
            reader = self.capture()
            self.assertEqual(reader.observe(qmp), [])
            result = reader.summary()
            self.assertEqual(result["read_error"], 1)
            self.assertNotIn("private", json.dumps(result))

    def test_diagnostic_failures_do_not_prevent_following_cleanup(self):
        for fail_at in ("read", "summary", "emit"):
            class Capture:
                def observe(self, qmp):
                    if fail_at == "read":
                        raise RuntimeError("private-read-error")
                def summary(self):
                    if fail_at == "summary":
                        raise RuntimeError("private-summary-error")
                    return {"diagnostic_only": True}
            def emit(stage, **value):
                if fail_at == "emit":
                    raise BrokenPipeError("private-output-error")
            cleanup_reached = False
            diagnostic.emit_terminal_summary(Capture(), None, emit)
            cleanup_reached = True
            self.assertTrue(cleanup_reached)

    def test_bootstrap_frames_do_not_satisfy_original_hello_protocol(self):
        reader = guest.SerialReader("A" * 48)
        self.assertEqual(reader.feed(b"GUEST_BOOTSTRAP_V1 10 0\nGUEST_BOOTSTRAP_V1 16 0\n"), [])
        self.assertFalse(reader.hello_verified)
        self.assertIsNone(reader.result)


if __name__ == "__main__":
    unittest.main()
