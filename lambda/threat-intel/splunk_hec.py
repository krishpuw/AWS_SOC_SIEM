import json
import os
from datetime import date, datetime
from decimal import Decimal

import requests

# Splunk HTTP Event Collector (HEC) forwarder.
#
# Env vars (set in SAM template, .env, or the shell for local testing):
#   HEC_URL         e.g. https://splunk.example.com:8088
#                   (the /services/collector/event path is appended if missing)
#   HEC_TOKEN       HEC token - never hardcode it
#   HEC_VERIFY_SSL  "false" to accept a self-signed cert (local Splunk only)

HEC_EVENT_PATH  = "/services/collector/event"
HEC_TIMEOUT_SEC = 5


def _hec_endpoint(url: str) -> str:
    url = url.rstrip("/")
    if "/services/collector" in url:
        return url
    return url + HEC_EVENT_PATH


def _json_default(obj):
    # DynamoDB items come back with Decimal numbers, json can't serialize them
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    return str(obj)


def is_configured() -> bool:
    return bool(os.environ.get("HEC_URL")) and bool(os.environ.get("HEC_TOKEN"))


def build_payload(event: dict, time=None, source=None, sourcetype="_json",
                  host=None, index=None, fields=None) -> dict:
    """
    Wrap an event dict in the HEC envelope. Optional fields are omitted when None.
    fields: flat dict of indexed fields (searchable as name::value).
    """
    payload = {"event": event, "sourcetype": sourcetype}
    if fields:
        payload["fields"] = fields
    if time is not None:
        payload["time"] = time
    if source is not None:
        payload["source"] = source
    if host is not None:
        payload["host"] = host
    if index is not None:
        payload["index"] = index
    return payload


def send_events(payloads: list) -> bool:
    """
    POST one or more HEC payloads (from build_payload) in a single request.
    HEC accepts multiple JSON objects concatenated in one body.
    Never raises - returns True on success, False otherwise, so callers
    can't be broken by Splunk being down.
    """
    if not payloads:
        return True

    url   = os.environ.get("HEC_URL", "")
    token = os.environ.get("HEC_TOKEN", "")
    if not url or not token:
        print("[i] HEC_URL / HEC_TOKEN not set, skipping Splunk forward")
        return False

    verify_ssl = os.environ.get("HEC_VERIFY_SSL", "true").lower() != "false"
    body = "\n".join(json.dumps(p, default=_json_default) for p in payloads)

    try:
        resp = requests.post(
            _hec_endpoint(url),
            data=body.encode("utf-8"),
            headers={
                "Authorization": f"Splunk {token}",
                "Content-Type":  "application/json",
            },
            timeout=HEC_TIMEOUT_SEC,
            verify=verify_ssl,
        )
    except requests.RequestException as e:
        print(f"[!] Splunk HEC request failed: {e}")
        return False

    if resp.status_code != 200:
        # HEC returns {"text": "...", "code": N} on errors - token is not echoed
        print(f"[!] Splunk HEC returned HTTP {resp.status_code}: {resp.text[:500]}")
        return False

    return True


def send_event(event: dict, **kwargs) -> bool:
    """POST a single JSON event to Splunk HEC. kwargs are passed to build_payload."""
    return send_events([build_payload(event, **kwargs)])
