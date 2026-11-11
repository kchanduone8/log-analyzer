import re
from collections import Counter
import csv
import sys

# Matches standard Common/Combined Log Format
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[.*?\] "(?P<method>[A-Z]+) (?P<endpoint>/\S*) HTTP/\d\.\d" (?P<status>\d{3}) (?P<size>\d+|-)'
)

def analyze_logs(file_path):
    ip_counter = Counter()
    status_counter = Counter()
    error_logs = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                match = LOG_PATTERN.search(line)
                if match:
                    data = match.groupdict()
                    ip = data['ip']
                    status = data['status']
                    
                    ip_counter[ip] += 1
                    status_counter[status] += 1
                    
                    # Track 4xx and 5xx client/server errors
                    if status.startswith(('4', '5')):
                        error_logs.append({
                            'line': line_num,
                            'ip': ip,
                            'method': data['method'],
                            'endpoint': data['endpoint'],
                            'status': status
                        })
    except FileNotFoundError:
        print(f"Error: Log file '{file_path}' not found.")
        sys.exit(1)

    return ip_counter, status_counter, error_logs

def export_summary(error_logs, output_csv="error_summary.csv"):
    if not error_logs:
        return
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['line', 'ip', 'method', 'endpoint', 'status'])
        writer.writeheader()
        writer.writerows(error_logs)
    print(f"[*] Exported {len(error_logs)} error incidents to {output_csv}")

if __name__ == "__main__":
    sample_file = "server.log"
    ips, statuses, errors = analyze_logs(sample_file)

    print("\n--- Top 5 Requesting IPs ---")
    for ip, count in ips.most_common(5):
        print(f"{ip}: {count} requests")

    print("\n--- HTTP Status Code Summary ---")
    for code, count in sorted(statuses.items()):
        print(f"HTTP {code}: {count} occurrences")

    export_summary(errors)
