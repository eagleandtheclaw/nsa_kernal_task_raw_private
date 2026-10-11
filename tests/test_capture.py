import hashlib
import lzma
from pathlib import Path
import subprocess
import tempfile
import unittest

import capture
import publisher
import public_export


class CaptureTests(unittest.TestCase):
    def test_public_export_omits_identifier_header_and_thread_address(self):
        section = (
            "Process:          kernel_task [0]\n"
            "UUID:             12345678-1234-1234-1234-123456789abc\n"
            "Num samples:      2 (1-2)\n"
            "  Thread 0x1234    Thread name \"private-name\"    2 samples (1-2)\n"
            "  *2  example_symbol (kernel + 12) [0xabc123]\n"
            "  Binary Images: /Users/nick/private\n"
        )
        report, threads, frames = public_export.sanitize({"body": {
            "schema": 1, "kernel_task_section": section, "kernel_task_num_samples": 2}})
        self.assertEqual((threads, frames), (1, 1))
        self.assertIn("example_symbol", report)
        self.assertNotIn("private-name", report)
        self.assertNotIn("/Users/", report)
        self.assertNotIn("0x", report)
        self.assertNotIn("12345678-", report)

    def test_public_export_rejects_private_frame(self):
        section = (
            "Process:          kernel_task [0]\nNum samples:      1 (1-1)\n"
            "  Thread 0x1234    1 sample (1)\n"
            "  *1  /Users/nick/private [0xabc123]\n"
        )
        with self.assertRaisesRegex(RuntimeError, "private field"):
            public_export.sanitize({"body": {"schema": 1,
                "kernel_task_section": section, "kernel_task_num_samples": 1}})

    def test_extracts_only_kernel_task(self):
        report = (
            "Date/Time: 2026-10-11 12:00:00 +0000\nDuration: 1.00s\n"
            "Process:          unrelated [42]\nNum samples: 2 (1-2)\n"
            "Process:          kernel_task [0]\nNum samples: 2 (1-2)\n"
            "  Thread 1 running\nProcess:          following [43]\nNum samples: 2 (1-2)\n"
        ).encode()
        section, count, date, duration = capture.extract_kernel_task(report)
        self.assertEqual(count, 2)
        self.assertIn("kernel_task [0]", section)
        self.assertNotIn("following", section)
        self.assertEqual(date, "2026-10-11 12:00:00 +0000")
        self.assertEqual(duration, "1.00s")

    def test_canonical_hash_stable(self):
        a = capture.canonical({"b": 2, "a": 1})
        b = capture.canonical({"a": 1, "b": 2})
        self.assertEqual(a, b)
        self.assertEqual(capture.sha256(a), hashlib.sha256(a).hexdigest())

    def test_signed_sample_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key"
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            old_key, old_public = capture.SIGNING_KEY, publisher.PUBLIC_KEY
            capture.SIGNING_KEY, publisher.PUBLIC_KEY = key, key.with_suffix(".pub")
            try:
                section = "Process:          kernel_task [0]\nNum samples:      1 (1-1)\n"
                body = {"sequence": 1, "previous_body_sha256": "0" * 64,
                        "kernel_task_pid": 0, "kernel_task_section": section,
                        "kernel_task_section_sha256": capture.sha256(section.encode())}
                raw = capture.canonical(body)
                record = {"body": body, "body_sha256": capture.sha256(raw), "signature": capture.sign(raw)}
                path = Path(directory) / "sample.json.xz"
                path.write_bytes(lzma.compress(capture.canonical(record)))
                verified, _ = publisher.read_sample(path)
                self.assertEqual(verified["body"]["sequence"], 1)
                record["body"]["sequence"] = 2
                path.write_bytes(lzma.compress(capture.canonical(record)))
                with self.assertRaises(RuntimeError):
                    publisher.read_sample(path)
            finally:
                capture.SIGNING_KEY, publisher.PUBLIC_KEY = old_key, old_public

    def test_targeted_report_preserves_full_raw_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key"
            subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            old_key, old_public = capture.SIGNING_KEY, publisher.PUBLIC_KEY
            capture.SIGNING_KEY, publisher.PUBLIC_KEY = key, key.with_suffix(".pub")
            try:
                report = "Date/Time: 2026-10-11 12:00:00 +0000\nDuration: 1.00s\nProcess:          kernel_task [0]\nNum samples:      1 (1-1)\n"
                section, count, _, _ = capture.extract_kernel_task(report.encode())
                body = {"schema": 2, "sequence": 1, "previous_body_sha256": "0" * 64,
                        "kernel_task_pid": 0, "kernel_task_num_samples": count,
                        "raw_target_report": report,
                        "raw_target_report_sha256": capture.sha256(report.encode()),
                        "kernel_task_section_sha256": capture.sha256(section.encode())}
                raw = capture.canonical(body)
                record = {"body": body, "body_sha256": capture.sha256(raw), "signature": capture.sign(raw)}
                path = Path(directory) / "target.json.xz"
                path.write_bytes(lzma.compress(capture.canonical(record)))
                publisher.read_sample(path)
                record["body"]["raw_target_report_sha256"] = "0" * 64
                record["body_sha256"] = capture.sha256(capture.canonical(record["body"]))
                path.write_bytes(lzma.compress(capture.canonical(record)))
                with self.assertRaises(RuntimeError):
                    publisher.read_sample(path)
            finally:
                capture.SIGNING_KEY, publisher.PUBLIC_KEY = old_key, old_public


if __name__ == "__main__":
    unittest.main()
