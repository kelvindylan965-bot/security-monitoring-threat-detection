#!/usr/bin/env python3
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs/auth_sample.log")
REPORT_FILE = Path("reports/detection_report.txt")
THRESHOLD = 3
WINDOW_SECONDS = 300

pattern = re.compile(
    r"^(\S+).*Failed password for .*? from "
    r"(\d{1,3}(?:\.\d{1,3}){3})"
)

failed_by_ip = defaultdict(list)
successful = failed = unparsed = 0

with LOG_FILE.open(encoding="utf-8") as log:
    for line in log:
        if "Accepted " in line:
            successful += 1
        elif "Failed password" in line:
            match = pattern.search(line)
            if not match:
                unparsed += 1
                continue
            try:
                timestamp = datetime.fromisoformat(
                    match.group(1).replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                unparsed += 1
                continue
            failed_by_ip[match.group(2)].append(timestamp)
            failed += 1

alerts = []
for ip, timestamps in failed_by_ip.items():
    timestamps.sort()
    left = 0
    for right, current in enumerate(timestamps):
        while current - timestamps[left] > WINDOW_SECONDS:
            left += 1
        count = right - left + 1
        if count >= THRESHOLD:
            alerts.append((ip, count, current))
            break

report = [
    "SECURITY MONITORING REPORT",
    "=" * 28,
    f"Input log: {LOG_FILE}",
    f"Successful login events: {successful}",
    f"Failed login events parsed: {failed}",
    f"Unparsed failed-login events: {unparsed}",
    f"Alert threshold: {THRESHOLD} failures within {WINDOW_SECONDS} seconds",
    "",
    "FAILED LOGIN COUNTS",
]
for ip, timestamps in sorted(failed_by_ip.items()):
    report.append(f"{ip}: {len(timestamps)}")

report += ["", "ALERTS"]
if alerts:
    for ip, count, _ in sorted(alerts):
        report.append(f"WARNING: {ip} reached {count} failures within the time window.")
else:
    report.append("No sources reached the alert threshold.")

REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
REPORT_FILE.write_text("\n".join(report) + "\n", encoding="utf-8")
print("\n".join(report))
print(f"\nReport saved to: {REPORT_FILE}")
