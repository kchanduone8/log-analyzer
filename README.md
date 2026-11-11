# Server Log & Access Incident Parser

A lightweight Python command-line tool that parses web server access logs
(Common/Combined Log Format), reports the top requesting IP addresses, and
summarizes 4xx/5xx HTTP error distributions.

## Features
- **Compiled regex parsing:** a precompiled pattern (`re.compile`) extracts the
  client IP, timestamp, HTTP method, endpoint and status code from each line.
- **Single-pass frequency counting:** `collections.Counter` tracks requests per
  IP and per status code in one pass over the file (O(N) time).
- **Error tracking:** records every 4xx/5xx request with its line number.
- **CSV export:** writes `error_summary.csv`, `top_ips.csv` and
  `status_summary.csv` into a `reports/` folder.
- **Robust input handling:** blank and malformed lines are skipped and counted;
  a missing file gives a clear error message.

## Usage
```bash
python log_analyzer.py                       # reads server.log
python log_analyzer.py server.log --top 10   # choose a file and top-N
python log_analyzer.py server.log --out out  # choose the report folder
```

## Sample Output
```
Parsed lines : 6
Skipped lines: 0 (did not match the log format)

--- Top 5 Requesting IPs ---
192.168.1.10: 3 requests
192.168.1.15: 2 requests
192.168.1.25: 1 requests

--- HTTP Status Code Summary ---
HTTP 200: 3 occurrences
HTTP 401: 1 occurrences
HTTP 404: 1 occurrences
HTTP 500: 1 occurrences
```

## Files
- `log_analyzer.py` - the analyzer
- `server.log` - small sample log for trying it out

## Requirements
Python 3.8+ (standard library only)

## Limitations / Future Work
- Expects Common/Combined Log Format; other formats are skipped.
- All error rows are held in memory before export (fine for small and
  medium logs).
- Possible additions: per-hour request counts, brute-force detection
  (many 401/403 from one IP), unit tests for the regex.
