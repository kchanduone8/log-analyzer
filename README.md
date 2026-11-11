# Server Log & Access Incident Parser

A lightweight, automated Python CLI utility designed to parse web server access logs, identify high-traffic IP anomalies, and categorize 4xx/5xx HTTP status code error distributions.

## Features
- **Compiled Regex Tokenization:** Utilizes precompiled regular expressions (`re.compile`) for efficient single-pass text parsing.
- **O(N) Frequency Analysis:** Employs `collections.Counter` to track client traffic and error rates with minimal memory overhead.
- **Automated Incident Export:** Dumps error incident metadata directly to CSV for diagnostic workflows.

## Usage
```bash
python log_analyzer.py
