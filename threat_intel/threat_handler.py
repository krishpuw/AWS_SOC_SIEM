import json
import os
import boto3
import urllib.request
import urllib.error
from datetime import datetime, timezone
from decimal import Decimal
from boto3.dynamodb.conditions import Attr

# env vars (set in SAM template or .env for local)
VIRUSTOTAL_API_KEY  = os.environ.get("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY   = os.environ.get("ABUSEIPDB_API_KEY", "")
DYNAMODB_TABLE_NAME = os.environ.get("DYNAMODB_TABLE_NAME", "security-alerts")
LOCAL_MODE          = os.environ.get("LOCAL_MODE", "false").lower() == "true"

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
    return boto3.resource("dynamodb")


#   VirusTotal 
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


#   AbuseIPDB 
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


# Severity upgrade logic 
def calculate_enriched_severity(original_severity: str, vt: dict, abuse: dict) -> str:
    """
    Upgrade severity based on threat intel findings.
    """
    severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    current_rank  = severity_rank.get(original_severity.upper(), 1)
    new_rank      = current_rank

    abuse_score = abuse.get("abuse_confidence_score", 0)
    vt_malicious = vt.get("malicious", 0)
    is_tor       = abuse.get("is_tor", False)

    if abuse_score >= 80 or vt_malicious >= 5:
        new_rank = max(new_rank, 3)   # HIGH
    if abuse_score >= 50 or is_tor:
        new_rank = max(new_rank, 2)   # MEDIUM

    rank_to_severity = {v: k for k, v in severity_rank.items()}
    return rank_to_severity.get(new_rank, original_severity)
