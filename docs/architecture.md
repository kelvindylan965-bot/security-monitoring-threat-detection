# Architecture

1. Input: a text file containing SSH-style authentication events.
2. Parsing: Python identifies failed-password events and extracts source IPs.
3. Aggregation: a counter tracks failures for each source.
4. Detection: three or more parsed failures trigger an alert.
5. Reporting: event totals, source counts, alerts, and parsing issues are saved.

## Limitations
The detector uses synthetic input, recognises one failure-message format,
counts across the whole file, and cannot determine intent from a log alone.
