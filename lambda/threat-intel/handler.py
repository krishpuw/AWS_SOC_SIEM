import json
import os
import boto3
import urllib.request
import urllib.error
from datetime import datetime, timezone
from decimal import Decimal
from boto3.dynamodb.conditions import Attr

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

# env vars (set in SAM template or .env for local)
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "security-alerts")
LOCAL_MODE          = os.environ.get("LOCAL_MODE", "false").lower() == "true"
VIRUSTOTAL_API_KEY  = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY   = os.environ.get("ABUSEIPDB_API_KEY", "")

DYNAMODB_ENDPOINT   = "http://localhost:8000" if LOCAL_MODE else None





# DynamoDB client
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


# VirusTotal
def query_virustotal(ip: str) -> dict:
    """
    Query VirusTotal IP report endpoint.
    Returns a dict with keys: malicious, suspicious, harmless, undetected,
    total_vendors, vt_link, error.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VT_API_KEY_MISSING"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(
        url,
        headers={"x-apikey": VIRUSTOTAL_API_KEY, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "total_vendors": sum(stats.values()),
            "vt_link":     f"https://www.virustotal.com/gui/ip-address/{ip}",
            "error":       None,
        }
    except urllib.error.HTTPError as e:
        return {"error": f"VT_HTTP_{e.code}"}
    except Exception as e:
        return {"error": f"VT_ERROR: {str(e)}"}


# AbuseIPDB
def query_abuseipdb(ip: str) -> dict:
    """
    Query AbuseIPDB check endpoint.
    Returns a dict with keys: abuse_confidence_score, usage_type, country_code,
    total_reports, last_reported_at, is_tor, error.
    """
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSE_API_KEY_MISSING"}

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
    req = urllib.request.Request(
        url,
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        d = data.get("data", {})
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "usage_type":             d.get("usageType", "unknown"),
            "country_code":           d.get("countryCode", "unknown"),
            "total_reports":          d.get("totalReports", 0),
            "last_reported_at":       d.get("lastReportedAt", None),
            "is_tor":                 d.get("isTor", False),
            "error":                  None,
        }
    except urllib.error.HTTPError as e:
        return {"error": f"ABUSE_HTTP_{e.code}"}
    except Exception as e:
        return {"error": f"ABUSE_ERROR: {str(e)}"}



def calculate_enriched_severity(original_severity: str, vt: dict, abuse: dict) -> str:
    """Upgrade severity based on threat intel findings."""
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    current_rank  = severity_rank.get(original_severity.upper(), 1)
    new_rank      = current_rank

    abuse_score  = abuse.get("abuse_confidence_score", 0)
    vt_malicious = vt.get("malicious", 0)
    is_tor       = abuse.get("is_tor", False)

    if abuse_score >= 80 or vt_malicious >= 5:
        new_rank = max(new_rank, 3)   # HIGH
    if abuse_score >= 50 or is_tor:
        new_rank = max(new_rank, 2)   # MEDIUM

    rank_to_severity = {v: k for k, v in severity_rank.items()}
    return rank_to_severity.get(new_rank, original_severity)


# DynamoDB helpers
def fetch_unenriched_alerts(table) -> list:
    """Scan for alerts that haven't been enriched yet."""
    resp = table.scan(FilterExpression=Attr("enriched").eq(False))
    return resp.get("Items", [])


def update_alert_with_enrichment(table, alert_id: str, enrichment: dict):
    """Write enrichment data back to the alert record."""
    def to_decimal(obj):
        if isinstance(obj, float):
            return Decimal(str(obj))
        if isinstance(obj, dict):
            return {k: to_decimal(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [to_decimal(i) for i in obj]
        return obj

    safe_enrichment = to_decimal(enrichment)

    table.update_item(
        Key={"alert_id": alert_id},
        UpdateExpression=(
            "SET threat_intel = :ti, "
            "    enriched = :en, "
            "    enriched_at = :ea, "
            "    severity = :sv"
        ),
        ExpressionAttributeValues={
            ":ti": safe_enrichment["threat_intel"],
            ":en": True,
            ":ea": enrichment["enriched_at"],
            ":sv": enrichment["upgraded_severity"],
        },
    )


# Core enrichment logic
def enrich_alert(alert: dict) -> dict:
    """Runs VT + AbuseIPDB enrichment and returns the enrichment payload."""
    source_ip         = alert.get("source_ip", "")
    original_severity = alert.get("severity", "LOW")

    print(f"[+] Enriching alert {alert.get('alert_id')} | IP: {source_ip}")

    vt    = query_virustotal(source_ip)
    abuse = query_abuseipdb(source_ip)

    upgraded_severity = calculate_enriched_severity(original_severity, vt, abuse)

    abuse_score  = abuse.get("abuse_confidence_score", 0)
    vt_malicious = vt.get("malicious", 0)

    if abuse_score >= 80 or vt_malicious >= 10:
        verdict = "MALICIOUS"
    elif abuse_score >= 50 or vt_malicious >= 3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "threat_intel": {
            "source_ip": source_ip,
            "verdict":   verdict,
            "virustotal": {
                "malicious":     vt.get("malicious", 0),
                "suspicious":    vt.get("suspicious", 0),
                "harmless":      vt.get("harmless", 0),
                "total_vendors": vt.get("total_vendors", 0),
                "vt_link":       vt.get("vt_link", ""),
                "error":         vt.get("error"),
            },
            "abuseipdb": {
                "confidence_score": abuse.get("abuse_confidence_score", 0),
                "usage_type":       abuse.get("usage_type", "unknown"),
                "country_code":     abuse.get("country_code", "unknown"),
                "total_reports":    abuse.get("total_reports", 0),
                "last_reported_at": abuse.get("last_reported_at"),
                "is_tor":           abuse.get("is_tor", False),
                "error":            abuse.get("error"),
            },
        },
        "upgraded_severity": upgraded_severity,
        "severity_upgraded": upgraded_severity != original_severity,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


# Lambda handler
def lambda_handler(event, context):
    """
    Entry point. Two modes:
      1. Scheduled (EventBridge) — enriches all unenriched alerts in DynamoDB
      2. Direct invocation with alert_id — enriches one specific alert
    """
    dynamodb = get_dynamodb()
    table    = dynamodb.Table(DYNAMODB_TABLE_NAME)

    results = {"enriched": [], "skipped": [], "errors": []}

    if "alert_id" in event:
        alert_id = event["alert_id"]
        resp  = table.get_item(Key={"alert_id": alert_id})
        alert = resp.get("Item")
        if not alert:
            return {"statusCode": 404, "body": f"Alert {alert_id} not found"}

        try:
            enrichment = enrich_alert(alert)
            update_alert_with_enrichment(table, alert_id, enrichment)
            results["enriched"].append(alert_id)
        except Exception as e:
            results["errors"].append({"alert_id": alert_id, "error": str(e)})

    else:
        alerts = fetch_unenriched_alerts(table)
        print(f"[*] Found {len(alerts)} unenriched alerts")

        for alert in alerts:
            alert_id  = alert.get("alert_id")
            source_ip = alert.get("source_ip", "")

            if not source_ip or source_ip.startswith(("10.", "192.168.", "172.")):
                print(f"[~] Skipping private IP alert {alert_id}")
                results["skipped"].append(alert_id)
                continue

            try:
                enrichment = enrich_alert(alert)
                update_alert_with_enrichment(table, alert_id, enrichment)
                results["enriched"].append(alert_id)
                print(f"[+] Enriched {alert_id} -> verdict: {enrichment['threat_intel']['verdict']} | severity: {enrichment['upgraded_severity']}")
            except Exception as e:
                print(f"[!] Failed to enrich {alert_id}: {e}")
                results["errors"].append({"alert_id": alert_id, "error": str(e)})

    print(f"[*] Done -- enriched: {len(results['enriched'])}, skipped: {len(results['skipped'])}, errors: {len(results['errors'])}")
    return {"statusCode": 200, "body": json.dumps(results)}




# # Local test
# if __name__ == "__main__":
#     VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
#     ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")

#     print("=== Threat Intel -- enriching real alerts from DynamoDB ===\n")
#     result = lambda_handler({}, None)
#     print("\n=== Result ===")
#     print(json.dumps(json.loads(result["body"]), indent=2))