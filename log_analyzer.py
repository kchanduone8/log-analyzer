import argparse
import csv
import os
import re
import sys
from collections import Counter

# Matches Common/Combined Log Format.
# Named groups: ip, timestamp, method, endpoint, status, size
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<endpoint>\S+) HTTP/\d(?:\.\d)?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
)


def analyze_logs(file_path):
    """Read the log once (single pass, O(N)) and build frequency counters."""
    ip_counter = Counter()
    status_counter = Counter()
    error_logs = []
    total = 0
    skipped = 0

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                match = LOG_PATTERN.search(line)
                if not match:
                    skipped += 1
                    continue

                data = match.groupdict()
                total += 1
                ip_counter[data['ip']] += 1
                status_counter[data['status']] += 1

                # Track 4xx (client) and 5xx (server) errors
                if data['status'].startswith(('4', '5')):
                    error_logs.append({
                        'line': line_num,
                        'ip': data['ip'],
                        'timestamp': data['timestamp'],
                        'method': data['method'],
                        'endpoint': data['endpoint'],
                        'status': data['status'],
                    })
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        sys.exit(1)

    return ip_counter, status_counter, error_logs, total, skipped


def export_csv(filename, fieldnames, rows):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_reports(ip_counter, status_counter, error_logs, out_dir, top_n):
    os.makedirs(out_dir, exist_ok=True)

    # 1) Every 4xx/5xx incident
    errors_path = os.path.join(out_dir, "error_summary.csv")
    export_csv(errors_path,
               ['line', 'ip', 'timestamp', 'method', 'endpoint', 'status'],
               error_logs)

    # 2) Top requesting IPs
    ips_path = os.path.join(out_dir, "top_ips.csv")
    export_csv(ips_path, ['ip', 'requests'],
               [{'ip': ip, 'requests': c} for ip, c in ip_counter.most_common(top_n)])

    # 3) Status code distribution
    status_path = os.path.join(out_dir, "status_summary.csv")
    export_csv(status_path, ['status', 'count'],
               [{'status': s, 'count': c} for s, c in sorted(status_counter.items())])

    print(f"\n[*] Exported {len(error_logs)} error incidents to {errors_path}")
    print(f"[*] Exported top {top_n} IPs to {ips_path}")
    print(f"[*] Exported status summary to {status_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a web server access log (Common/Combined Log Format).")
    parser.add_argument("logfile", nargs="?", default="server.log",
                        help="path to the access log (default: server.log)")
    parser.add_argument("--top", type=int, default=5,
                        help="number of top IPs to show (default: 5)")
    parser.add_argument("--out", default="reports",
                        help="folder for CSV reports (default: reports)")
    args = parser.parse_args()

    ips, statuses, errors, total, skipped = analyze_logs(args.logfile)

    print(f"Parsed lines : {total}")
    print(f"Skipped lines: {skipped} (did not match the log format)")

    print(f"\n--- Top {args.top} Requesting IPs ---")
    for ip, count in ips.most_common(args.top):
        print(f"{ip}: {count} requests")

    print("\n--- HTTP Status Code Summary ---")
    for code, count in sorted(statuses.items()):
        print(f"HTTP {code}: {count} occurrences")

    if errors:
        export_reports(ips, statuses, errors, args.out, args.top)
    else:
        print("\nNo 4xx/5xx errors found, so no error CSV was created.")


if __name__ == "__main__":
    main()
