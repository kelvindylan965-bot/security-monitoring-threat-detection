# Security Monitoring & Threat Detection Lab

A Python defensive-security project that analyses SSH-style authentication
logs, groups failed login attempts by source IP, flags repeated failures,
and generates a text report.

## Features
- Counts successful login events.
- Groups failed-password events by source IP.
- Flags sources with three or more parsed failures.
- Reports failed-login events that could not be parsed.
- Includes three automated tests.

## Run
From the project root:

    python3 scripts/detect_failed_logins.py
    python3 -m unittest discover -s tests -v

To analyse another log file:

    python3 scripts/detect_failed_logins.py path/to/auth.log

The report is saved to `reports/detection_report.txt`.

## Safety and limitations
The included log is synthetic and uses documentation-only IP addresses.
An alert indicates activity worth investigating; it does not prove an attack.
This version counts failures across the entire file, not a time window, and
does not ingest live logs. It is a learning prototype, not a production tool.
