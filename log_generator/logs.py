import json
import random
import time
from datetime import datetime, timedelta, timezone
import os

#logs 
OUTPUT_DIR = "sample-logs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Known malicious IPs (simulate threat intel hits)
MALICIOUS_IPS = ["185.220.101.45", "45.33.32.156", "103.21.244.0", "198.54.117.197",  "91.108.4.1", "179.60.147.31", "103.216.221.19",]
NORMAL_IPS     = [f"192.168.1.{i}" for i in range(1, 20)] + \
                 [f"10.0.0.{i}" for i in range(1, 10)]
ALL_IPS        = MALICIOUS_IPS + NORMAL_IPS

USERNAMES      = ["admin", "root", "ubuntu", "ec2-user", "krish", "john", "guest", "test"]
VALID_USERS    = ["krish", "john"]

WIN_EVENT_IDS  = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4672: "Special Privileges Assigned",
    4720: "User Account Created",
    4728: "User Added to Security Group",
    4732: "User Added to Local Group",
}

WEB_PATHS = [
    "/", "/index.html", "/login", "/admin", "/wp-admin",
    "/etc/passwd", "/../../../etc/passwd",           # path traversal
    "/search?q=<script>alert(1)</script>",           # XSS attempt
    "/api/users", "/api/admin", "/.env", "/.git",
    "/phpmyadmin", "/shell.php", "/cmd.php"
]
WEB_METHODS    = ["GET", "POST", "PUT", "DELETE"]
WEB_STATUS     = [200, 200, 200, 301, 302, 400, 401, 403, 404, 500]
USER_AGENTS    = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/7.68.0",
    "python-requests/2.25.1",
    "Nikto/2.1.6",        # vulnerability scanner
    "sqlmap/1.4",         # SQLi tool
    "masscan/1.3",        # port scanner
]

#mitre attack 
def get_attack_tag(event_type):
    mapping = {
        "ssh_brute_force":        {"technique_id": "T1110.001", "technique": "Brute Force: Password Guessing"},
        "ssh_success":            {"technique_id": "T1078",     "technique": "Valid Accounts"},
        "win_failed_logon":       {"technique_id": "T1110",     "technique": "Brute Force"},
        "win_privilege_assigned": {"technique_id": "T1548",     "technique": "Abuse Elevation Control Mechanism"},
        "win_account_created":    {"technique_id": "T1136",     "technique": "Create Account"},
        "win_group_modified":     {"technique_id": "T1098",     "technique": "Account Manipulation"},
        "web_path_traversal":     {"technique_id": "T1083",     "technique": "File and Directory Discovery"},
        "web_xss":                {"technique_id": "T1059.007", "technique": "Command and Scripting Interpreter: JavaScript"},
        "web_scanner":            {"technique_id": "T1046",     "technique": "Network Service Discovery"},
        "web_sensitive_file":     {"technique_id": "T1083",     "technique": "File and Directory Discovery"},
        "web_normal":             None,
        "win_success_logon":      None,
    }
    return mapping.get(event_type, None)


def random_timestamp(hours_back=24):
    now = datetime.now(timezone.utc)
    delta = timedelta(seconds=random.randint(0, hours_back * 3600))
    return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")

#ssh
def generate_ssh_logs(n=100):
    logs = []
    for _ in range(n):
        ip       = random.choice(ALL_IPS)
        user     = random.choice(USERNAMES)
        ts       = random_timestamp()
        is_malicious = ip in MALICIOUS_IPS

        # Simulate brute force: malicious IPs fail more
        if is_malicious:
            success = random.random() < 0.05
        else:
            success = random.random() < 0.85

        event_type = "ssh_success" if success else "ssh_brute_force"
        attack     = get_attack_tag(event_type)

        log = {
            "log_type":   "ssh",
            "timestamp":  ts,
            "source_ip":  ip,
            "username":   user,
            "status":     "success" if success else "failed",
            "event_type": event_type,
            "is_malicious_ip": is_malicious,
            "mitre_attack": attack,
            "raw": f"{ts} sshd[{random.randint(1000,9999)}]: "
                   f"{'Accepted' if success else 'Failed'} password for {user} "
                   f"from {ip} port {random.randint(1024, 65535)} ssh2"
        }
        logs.append(log)
    return logs

#windows events 
def generate_windows_logs(n=100):
    logs = []
    event_ids = list(WIN_EVENT_IDS.keys())

    for _ in range(n):
        ip       = random.choice(ALL_IPS)
        user     = random.choice(USERNAMES)
        ts       = random_timestamp()
        event_id = random.choice(event_ids)
        desc     = WIN_EVENT_IDS[event_id]
        is_malicious = ip in MALICIOUS_IPS

        # Map event to type
        if event_id == 4625:
            event_type = "win_failed_logon"
        elif event_id == 4624:
            event_type = "win_success_logon"
        elif event_id == 4672:
            event_type = "win_privilege_assigned"
        elif event_id == 4720:
            event_type = "win_account_created"
        else:
            event_type = "win_group_modified"

        attack = get_attack_tag(event_type)

        log = {
            "log_type":        "windows_event",
            "timestamp":       ts,
            "event_id":        event_id,
            "event_description": desc,
            "source_ip":       ip,
            "username":        user,
            "event_type":      event_type,
            "is_malicious_ip": is_malicious,
            "mitre_attack":    attack,
            "raw": f"EventID={event_id} | TimeCreated={ts} | "
                   f"SubjectUserName={user} | IpAddress={ip} | Description={desc}"
        }
        logs.append(log)
    return logs


#web server
def classify_web_event(path, user_agent):
    if any(x in path for x in ["passwd", "../", "%2e%2e"]):
        return "web_path_traversal"
    if "<script>" in path or "alert(" in path:
        return "web_xss"
    if any(x in path for x in [".env", ".git", "phpmyadmin", "shell.php", "cmd.php"]):
        return "web_sensitive_file"
    if any(x in user_agent for x in ["Nikto", "sqlmap", "masscan"]):
        return "web_scanner"
    return "web_normal"

def generate_web_logs(n=100):
    logs = []
    for _ in range(n):
        ip         = random.choice(ALL_IPS)
        method     = random.choice(WEB_METHODS)
        path       = random.choice(WEB_PATHS)
        status     = random.choice(WEB_STATUS)
        user_agent = random.choice(USER_AGENTS)
        ts         = random_timestamp()
        bytes_sent = random.randint(200, 50000)
        is_malicious = ip in MALICIOUS_IPS
        event_type = classify_web_event(path, user_agent)
        attack     = get_attack_tag(event_type)

        log = {
            "log_type":        "web",
            "timestamp":       ts,
            "source_ip":       ip,
            "method":          method,
            "path":            path,
            "status_code":     status,
            "bytes_sent":      bytes_sent,
            "user_agent":      user_agent,
            "event_type":      event_type,
            "is_malicious_ip": is_malicious,
            "mitre_attack":    attack,
            "raw": f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "{user_agent}"'
        }
        logs.append(log)
    return logs



def main():

    ssh_logs  = generate_ssh_logs(100)
    win_logs  = generate_windows_logs(100)
    web_logs  = generate_web_logs(100)

    all_logs  = ssh_logs + win_logs + web_logs
    random.shuffle(all_logs)

    # Write combined log file
    combined_path = os.path.join(OUTPUT_DIR, "security_logs.json")
    with open(combined_path, "w") as f:
        json.dump(all_logs, f, indent=2)

    # Write individual log files
    for name, logs in [("ssh_logs", ssh_logs), ("windows_logs", win_logs), ("web_logs", web_logs)]:
        path = os.path.join(OUTPUT_DIR, f"{name}.json")
        with open(path, "w") as f:
            json.dump(logs, f, indent=2)

    # Summary
    print(f"Generated {len(all_logs)} total log entries")
    print(f"   • SSH logs:     {len(ssh_logs)}")
    print(f"   • Windows logs: {len(win_logs)}")
    print(f"   • Web logs:     {len(web_logs)}")

    malicious = [l for l in all_logs if l.get("is_malicious_ip")]
    print(f"Logs from known malicious IPs: {len(malicious)}")

    mitre_hits = [l for l in all_logs if l.get("mitre_attack")]
    techniques = {}
    for l in mitre_hits:
        t = l["mitre_attack"]["technique_id"]
        techniques[t] = techniques.get(t, 0) + 1

    print(f"\ MITRE ATT&CK Techniques Detected:")
    for tid, count in sorted(techniques.items()):
        name = next(l["mitre_attack"]["technique"] for l in mitre_hits if l["mitre_attack"]["technique_id"] == tid)
        print(f"   • {tid} — {name}: {count} events")

    print(f" Output files written to ./{OUTPUT_DIR}/")
    print(f"   • security_logs.json (all combined)")
    print(f"   • ssh_logs.json")
    print(f"   • windows_logs.json")
    print(f"   • web_logs.json")

if __name__ == "__main__":
    main()