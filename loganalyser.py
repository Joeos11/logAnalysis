import re
from collections import defaultdict
from datetime import datetime

log_file = "sample_logs/auth.log"

failed_logins = defaultdict(int)
login_times = []

# Regex patterns


failed_pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
success_pattern = re.compile(r"Accepted password.*from (\d+\.\d+\.\d+\.\d+)")
time_pattern = re.compile(r"(\w+\s+\d+\s+\d+:\d+:\d+)")

def parse_time(time_str):
    return datetime.strptime(time_str, "%b %d %H:%M:%S")

with open(log_file, "r") as file:
    for line in file:
        
        # Extract timestamp
        time_match = time_pattern.search(line)
        if time_match:
            timestamp = parse_time(time_match.group(1))
            login_times.append(timestamp)

        # Detect failed logins
        failed_match = failed_pattern.search(line)
        if failed_match:
            ip = failed_match.group(1)
            failed_logins[ip] += 1

# Detect suspicious activity
print("\n--- Suspicious Activity Report ---\n")

# Repeated failed logins
for ip, count in failed_logins.items():
    if count >= 3:
        print(f"[ALERT] Multiple failed logins from {ip}: {count} attempts")

# Unusual login times (e.g. 00:00–05:00)
for t in login_times:
    if t.hour < 5:
        print(f"[WARNING] Login at unusual time: {t}")
