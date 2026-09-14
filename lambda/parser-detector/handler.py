import json
import os
import re
import uuid
import boto3
from collections import defaultdict
from datetime import datetime, timezone, timedelta

import splunk_hec

# Local .env loader — only active when running directly 
if __name__ == "__main__" or os.environ.get("LOCAL_MODE") == "true":
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, val = line.partition("=")
                    os.environ.setdefault(key.strip(), val.strip())

# env vars 
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "security-alerts")
LOCAL_MODE          = os.environ.get("LOCAL_MODE", "false").lower() == "true"
LOG_BUCKET          = os.environ.get("LOG_BUCKET", "")
# HEC_URL / HEC_TOKEN are read by splunk_hec.py at send time

SPLUNK_SOURCE       = "cloud-siem:parser-detector"
SPLUNK_BATCH_SIZE   = 100   # alerts per HEC request

DYNAMODB_ENDPOINT   = "http://localhost:8000" if LOCAL_MODE else None

# detection rules 
SSH_BRUTE_FORCE_THRESHOLD   = 5     # failed logins
SSH_BRUTE_FORCE_WINDOW_SEC  = 60

PORT_SCAN_DISTINCT_PATHS    = 10    # distinct paths hit
PORT_SCAN_WINDOW_SEC        = 60

WIN_FAILED_LOGON_THRESHOLD  = 5
WIN_FAILED_LOGON_WINDOW_SEC = 60

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"union.*select",
    r"select.*from",
    r"drop\s+table",
    r"or\s+1\s*=\s*1",
    r"' or '",
    r"exec(\s|\+)+(s|x)p\w+",
]

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.%2f",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"etc/passwd",
    r"boot\.ini",
]


#dynamodb
def get_dynamodb():
    if LOCAL_MODE:
        return boto3.resource(
            "dynamodb",
            region_name="us-east-1",
            endpoint_url=DYNAMODB_ENDPOINT,
            aws_access_key_id="dummy",
            aws_secret_access_key="dummy",
        )
    return boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"))



def parse_timestamp(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def make_alert(rule_name, tactic, technique_id, technique_name, severity,
               source_ip, description, evidence, log_type):
    now = datetime.now(timezone.utc)
    ttl = int((now + timedelta(days=90)).timestamp())
    return {
        "alert_id":     str(uuid.uuid4()),
        "timestamp":    now.isoformat(),
        "rule_name":    rule_name,
        "log_type":     log_type,
        "source_ip":    source_ip,
        "severity":     severity,
        "description":  description,
        "evidence":     evidence,
        "mitre_attack": {
            "tactic":         tactic,
            "technique_id":   technique_id,
            "technique_name": technique_name,
        },
        "enriched": False,
        "ttl": ttl,
    }


#ssh bf
def detect_ssh_brute_force(logs):
    """5+ failed SSH logins from the same IP within 60 seconds."""
    alerts = []
    ssh_logs = [l for l in logs if l.get("log_type") == "ssh" and l.get("status") == "failed"]

    by_ip = defaultdict(list)
    for log in ssh_logs:
        by_ip[log["source_ip"]].append(log)

    for ip, entries in by_ip.items():
        entries.sort(key=lambda l: l["timestamp"])
        for i in range(len(entries)):
            window_start = parse_timestamp(entries[i]["timestamp"])
            window = [
                e for e in entries[i:]
                if (parse_timestamp(e["timestamp"]) - window_start).total_seconds() <= SSH_BRUTE_FORCE_WINDOW_SEC
            ]
            if len(window) >= SSH_BRUTE_FORCE_THRESHOLD:
                alerts.append(make_alert(
                    rule_name="ssh_brute_force",
                    tactic="Credential Access",
                    technique_id="T1110.001",
                    technique_name="Brute Force: Password Guessing",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"{len(window)} failed SSH logins from {ip} within {SSH_BRUTE_FORCE_WINDOW_SEC}s",
                    evidence=[e["raw"] for e in window[:10]],
                    log_type="ssh",
                ))
                break  # one alert per IP is enough
    return alerts


# proxy ip hits and scans port
def detect_port_scan(logs):
    alerts = []
    web_logs = [l for l in logs if l.get("log_type") == "web"]

    by_ip = defaultdict(list)
    for log in web_logs:
        by_ip[log["source_ip"]].append(log)

    for ip, entries in by_ip.items():
        entries.sort(key=lambda l: l["timestamp"])
        for i in range(len(entries)):
            window_start = parse_timestamp(entries[i]["timestamp"])
            window = [
                e for e in entries[i:]
                if (parse_timestamp(e["timestamp"]) - window_start).total_seconds() <= PORT_SCAN_WINDOW_SEC
            ]
            distinct_paths = set(e["path"] for e in window)
            if len(distinct_paths) >= PORT_SCAN_DISTINCT_PATHS:
                alerts.append(make_alert(
                    rule_name="port_scan",
                    tactic="Reconnaissance",
                    technique_id="T1046",
                    technique_name="Network Service Discovery",
                    severity="MEDIUM",
                    source_ip=ip,
                    description=f"{ip} probed {len(distinct_paths)} distinct paths within {PORT_SCAN_WINDOW_SEC}s",
                    evidence=[e["raw"] for e in window[:10]],
                    log_type="web",
                ))
                break
    return alerts


# failed window logins
def detect_windows_failed_logins(logs):
    """5+ failed Windows logon events (4625) from same IP within 60 seconds."""
    alerts = []
    win_logs = [
        l for l in logs
        if l.get("log_type") == "windows_event" and l.get("event_id") == 4625
    ]

    by_ip = defaultdict(list)
    for log in win_logs:
        by_ip[log["source_ip"]].append(log)

    for ip, entries in by_ip.items():
        entries.sort(key=lambda l: l["timestamp"])
        for i in range(len(entries)):
            window_start = parse_timestamp(entries[i]["timestamp"])
            window = [
                e for e in entries[i:]
                if (parse_timestamp(e["timestamp"]) - window_start).total_seconds() <= WIN_FAILED_LOGON_WINDOW_SEC
            ]
            if len(window) >= WIN_FAILED_LOGON_THRESHOLD:
                alerts.append(make_alert(
                    rule_name="windows_failed_logon_burst",
                    tactic="Credential Access",
                    technique_id="T1110",
                    technique_name="Brute Force",
                    severity="HIGH",
                    source_ip=ip,
                    description=f"{len(window)} failed Windows logons (4625) from {ip} within {WIN_FAILED_LOGON_WINDOW_SEC}s",
                    evidence=[e["raw"] for e in window[:10]],
                    log_type="windows_event",
                ))
                break
    return alerts


# sql injectiona ttack
def detect_sql_injection(logs):
    """Web request path matches known SQLi patterns."""
    alerts = []
    web_logs = [l for l in logs if l.get("log_type") == "web"]

    for log in web_logs:
        path = log.get("path", "").lower()
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                alerts.append(make_alert(
                    rule_name="sql_injection_attempt",
                    tactic="Initial Access",
                    technique_id="T1190",
                    technique_name="Exploit Public-Facing Application",
                    severity="HIGH",
                    source_ip=log["source_ip"],
                    description=f"SQL injection pattern detected in request path from {log['source_ip']}",
                    evidence=[log["raw"]],
                    log_type="web",
                ))
                break  # one match is enough for this log entry
    return alerts


# directory traversal
def detect_directory_traversal(logs):
    """Web request path matches directory traversal patterns."""
    alerts = []
    web_logs = [l for l in logs if l.get("log_type") == "web"]

    for log in web_logs:
        path = log.get("path", "").lower()
        for pattern in TRAVERSAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                alerts.append(make_alert(
                    rule_name="directory_traversal",
                    tactic="Discovery",
                    technique_id="T1083",
                    technique_name="File and Directory Discovery",
                    severity="MEDIUM",
                    source_ip=log["source_ip"],
                    description=f"Directory traversal pattern detected in request path from {log['source_ip']}",
                    evidence=[log["raw"]],
                    log_type="web",
                ))
                break
    return alerts



def run_detection_rules(logs):
    all_alerts = []
    all_alerts.extend(detect_ssh_brute_force(logs))
    all_alerts.extend(detect_port_scan(logs))
    all_alerts.extend(detect_windows_failed_logins(logs))
    all_alerts.extend(detect_sql_injection(logs))
    all_alerts.extend(detect_directory_traversal(logs))
    return all_alerts


#alerts to db
def write_alerts(table, alerts):
    written = 0
    for alert in alerts:
        try:
            table.put_item(Item=alert)
            written += 1
        except Exception as e:
            print(f"[!] Failed to write alert {alert.get('alert_id')}: {e}")
    return written


#alerts to splunk hec
def forward_alerts_to_splunk(alerts, source=SPLUNK_SOURCE):
    """
    Sends alerts to Splunk HEC in batches. Runs after the DynamoDB write and
    never raises, so a Splunk outage can't fail the Lambda or lose DB writes.
    Returns the number of alerts accepted by HEC.
    """
    if not alerts:
        return 0
    if not splunk_hec.is_configured():
        print("[i] HEC_URL / HEC_TOKEN not set, skipping Splunk forward")
        return 0

    sent = 0
    for i in range(0, len(alerts), SPLUNK_BATCH_SIZE):
        batch = alerts[i:i + SPLUNK_BATCH_SIZE]
        payloads = []
        for alert in batch:
            try:
                event_time = datetime.fromisoformat(alert["timestamp"]).timestamp()
            except (KeyError, ValueError):
                event_time = None
            payloads.append(splunk_hec.build_payload(alert, time=event_time, source=source))

        try:
            if splunk_hec.send_events(payloads):
                sent += len(batch)
        except Exception as e:
            print(f"[!] Unexpected error forwarding alerts to Splunk: {e}")
    return sent


#
def lambda_handler(event, context):
    """
    Triggered by S3 ObjectCreated event. Reads the uploaded log file,
    runs detection rules, writes alerts to DynamoDB.
    """
    dynamodb = get_dynamodb()
    table    = dynamodb.Table(DYNAMODB_TABLE_NAME)

    s3 = boto3.client("s3")

    total_alerts = 0
    total_sent   = 0

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key    = record["s3"]["object"]["key"]

        print(f"[+] Processing s3://{bucket}/{key}")

        obj = s3.get_object(Bucket=bucket, Key=key)
        logs = json.loads(obj["Body"].read())

        if isinstance(logs, dict):
            logs = [logs]

        alerts = run_detection_rules(logs)
        written = write_alerts(table, alerts)
        total_alerts += written

        print(f"[+] {len(alerts)} alerts generated, {written} written to DynamoDB")

        sent = forward_alerts_to_splunk(alerts, source=f"s3://{bucket}/{key}")
        total_sent += sent
        print(f"[+] {sent}/{len(alerts)} alerts sent to Splunk HEC")

    return {
        "statusCode": 200,
        "body": json.dumps({"alerts_written": total_alerts, "alerts_sent_to_splunk": total_sent}),
    }


#testing
if __name__ == "__main__":
    logs_path = os.path.join(
        os.path.dirname(__file__), "..", "log_generator", "sample-logs", "security_logs.json"
    )

    if not os.path.exists(logs_path):
        print(f"[!] Logs file not found at: {logs_path}")
        print("    Run logs.py first, then re-run this script.")
        raise SystemExit(1)

    with open(logs_path) as f:
        logs = json.load(f)

    print(f"Loaded {len(logs)} log entries\n")

    alerts = run_detection_rules(logs)
    print(f"=== Detection complete: {len(alerts)} alerts generated ===\n")

    by_rule = defaultdict(int)
    for a in alerts:
        by_rule[a["rule_name"]] += 1

    for rule, count in by_rule.items():
        print(f"  {rule:<30} {count} alert(s)")

    print()
    for a in alerts:
        print(f"[{a['severity']:<8}] {a['rule_name']:<25} | {a['source_ip']:<18} | {a['mitre_attack']['technique_id']} - {a['mitre_attack']['technique_name']}")
        print(f"           {a['description']}")

    # Write to local DynamoDB if LOCAL_MODE is set
    if LOCAL_MODE:
        print("\n=== Writing alerts to local DynamoDB ===")
        dynamodb = get_dynamodb()
        table    = dynamodb.Table(DYNAMODB_TABLE_NAME)
        written = write_alerts(table, alerts)
        print(f"[+] {written}/{len(alerts)} alerts written to DynamoDB table '{DYNAMODB_TABLE_NAME}'")
    else:
        print("\n[i] Set LOCAL_MODE=true in .env to write these alerts to local DynamoDB")

    # Send to Splunk HEC - token is prompted for, never stored in code
    if os.environ.get("HEC_URL"):
        if not os.environ.get("HEC_TOKEN"):
            import getpass
            os.environ["HEC_TOKEN"] = getpass.getpass("Splunk HEC token: ")
        print("\n=== Sending alerts to Splunk HEC ===")
        sent = forward_alerts_to_splunk(alerts, source="cloud-siem:local-test")
        print(f"[+] {sent}/{len(alerts)} alerts sent to Splunk HEC at {os.environ['HEC_URL']}")
    else:
        print("[i] Set HEC_URL (and optionally HEC_TOKEN) to also send these alerts to Splunk")