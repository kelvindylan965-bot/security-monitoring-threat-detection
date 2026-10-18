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



    def test_failures_outside_five_minute_window_do_not_alert(self):
        log = "\\n".join([
            "2026-10-18T10:00:00Z host sshd[1]: Failed password for admin from 198.51.100.25 port 51001 ssh2",
            "2026-10-18T10:03:00Z host sshd[2]: Failed password for admin from 198.51.100.25 port 51002 ssh2",
            "2026-10-18T10:06:00Z host sshd[3]: Failed password for admin from 198.51.100.25 port 51003 ssh2",
        ]) + "\\n"
        output = self.run_detector(log)
        self.assertIn("No sources reached the alert threshold.", output)


    def test_malformed_log_line_does_not_crash(self):
        output = self.run_detector("this is not a valid authentication log\\n")
        self.assertIn("Unparsed failed-login events: 0", output)
        self.assertIn("No sources reached the alert threshold.", output)

    def test_invalid_timestamp_is_counted_as_unparsed(self):
        log = "NOT-A-TIME host sshd[1]: Failed password for admin from 198.51.100.25 port 51001 ssh2\\n"
        output = self.run_detector(log)
        self.assertIn("Unparsed failed-login events: 1", output)
        self.assertIn("No sources reached the alert threshold.", output)

if __name__ == "__main__":
    unittest.main()
