import win32evtlog  # Windows Event Log API
import re
from collections import defaultdict

# Brute-force detection settings
ALERT_THRESHOLD = 3  # Number of failed attempts before alert
failed_attempts = defaultdict(int)

def get_failed_logins():
    server = "localhost"
    log_type = "Security"

    # Open Windows Security Log
    hand = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = 0

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break

        for event in events:
            if event.EventID == 4625:  # Windows Event ID for failed login
                message = event.StringInserts
                if message:
                    user_ip = extract_ip(str(message))
                    if user_ip:
                        failed_attempts[user_ip] += 1
                        if failed_attempts[user_ip] >= ALERT_THRESHOLD:
                            print(f"🚨 ALERT: Possible brute-force attack from IP {user_ip}")

def extract_ip(event_message):
    # Extract IP address from event message
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", event_message)
    return match.group(0) if match else None

if __name__ == "__main__":
    print("🔍 Monitoring Windows failed login attempts...")
    get_failed_logins()
