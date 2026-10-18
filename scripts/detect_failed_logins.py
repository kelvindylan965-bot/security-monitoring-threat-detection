#!/usr/bin/env python3
import re
import sys
from collections import Counter
from pathlib import Path

LOG_FILE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("logs/auth_sample.log")
REPORT_FILE = Path("reports/detection_report.txt")
THRESHOLD = 3

failed_by_ip = Counter()
successful = 0
failed = 0
unparsed = 0

pattern = re.compile(r"Failed password for .*? from (\d{1,3}(?:\.\d{1,3}){3})")

with LOG_FILE.open(encoding="utf-8") as log:
    for line in log:
        if "Accepted " in line:
            successful += 1
        elif "Failed password" in line:
            match = pattern.search(line)
            if match:
                failed_by_ip[match.group(1)] += 1
                failed += 1
            else:
                unparsed += 1

alerts = [
    (ip, count)
    for ip, count in failed_by_ip.items()
    if count >= THRESHOLD
]

report = [
    "SECURITY MONITORING REPORT",
    "=" * 28,
    f"Input log: {LOG_FILE}",
    f"Successful login events: {successful}",
    f"Failed login events parsed: {failed}",
    f"Unparsed failed-login events: {unparsed}",
    f"Unique source IPs with failures: {len(failed_by_ip)}",
    f"Alert threshold: {THRESHOLD} failures per source IP",
    "",
    "FAILED LOGIN COUNTS",
]

for ip, count in sorted(failed_by_ip.items()):
    report.append(f"{ip}: {count}")

report += ["", "ALERTS"]
if alerts:
    for ip, count in sorted(alerts):
        report.append(f"WARNING: {ip} generated {count} failed login attempts.")
else:
    report.append("No sources reached the alert threshold.")

REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
REPORT_FILE.write_text("\n".join(report) + "\n", encoding="utf-8")

print("\n".join(report))
print(f"\nReport saved to: {REPORT_FILE}")
