import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/detect_failed_logins.py"


class DetectorTests(unittest.TestCase):
    def run_detector(self, contents):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "auth.log"
            log.write_text(contents, encoding="utf-8")
            result = subprocess.run(
                ["python3", str(SCRIPT), str(log)],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout

    def test_repeated_failures_trigger_alert(self):
        log = "".join(
            f"2026-10-18T10:0{i}:00Z host sshd[1]: "
            f"Failed password for admin from 198.51.100.25 port 5100{i} ssh2\n"
            for i in range(3)
        )
        output = self.run_detector(log)
        self.assertIn("198.51.100.25 reached 3 failures within the time window", output)

    def test_single_failure_does_not_trigger_alert(self):
        log = (
            "2026-10-18T10:00:00Z host sshd[1]: "
            "Failed password for test from 203.0.113.50 port 51001 ssh2\n"
        )
        output = self.run_detector(log)
        self.assertIn("No sources reached the alert threshold.", output)

    def test_successful_login_is_counted(self):
        log = (
            "2026-10-18T10:00:00Z host sshd[1]: "
            "Accepted publickey for kelvin from 192.0.2.10 port 51001 ssh2\n"
        )
        output = self.run_detector(log)
        self.assertIn("Successful login events: 1", output)
        self.assertIn("Failed login events parsed: 0", output)


if __name__ == "__main__":
    unittest.main()
