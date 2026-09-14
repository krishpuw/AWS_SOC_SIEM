# Mini Cloud-Native SIEM

A serverless Security Information and Event Management (SIEM) pipeline built on AWS. Ingests multi-source security logs, runs detection rules mapped to MITRE ATT&CK, enriches alerts with live threat intelligence, stores triage-ready alerts in DynamoDB, and forwards every alert to Splunk via HTTP Event Collector (HEC) for dashboards and investigation.

Built end-to-end with infrastructure as code — the entire stack deploys with a single `sam deploy`.

---

## Architecture

```
                  ┌──────────────────┐
  Log sources  →  │   S3 Bucket      │  cloud-siem-logs-dev-<account>
  (ssh / web /    │  (log ingestion) │  Versioned · lifecycle → IA → Glacier
   windows)       └────────┬─────────┘
                           │  s3:ObjectCreated (*.json)
                           ▼
                  ┌──────────────────────────────┐
                  │  Lambda: parser-detector     │
                  │  • normalizes 3 log formats  │
                  │  • 5 detection rules         │  --> Splunk HEC (detected alert)
                  │  • MITRE ATT&CK tagging      │
                  └────────┬─────────────────────┘
                           │  put_item
                           ▼
                  ┌──────────────────────────────┐
                  │  DynamoDB: security-alerts   │
                  │  PK: alert_id                │
                  │  GSI: severity + timestamp   │
                  │  TTL: 90-day auto-expiry     │
                  └────────┬─────────────────────┘
                           │  scan (enriched = false)
                           ▼
                  ┌──────────────────────────────┐
                  │  Lambda: threat-intel        │  ← EventBridge, rate(15 min)
                  │  • VirusTotal reputation     │
                  │  • AbuseIPDB confidence      │  --> Splunk HEC (enriched alert)
                  │  • severity upgrade logic    │
                  └──────────────────────────────┘
```

**Design notes**

- **Event-driven, not polled.** Parsing is triggered by the S3 upload itself; no scheduler, no idle compute.
- **Decoupled enrichment.** Threat-intel runs on its own schedule so third-party API latency and rate limits never block detection.
- **Least-privilege IAM.** The parser gets S3 read + DynamoDB write. Threat-intel gets DynamoDB CRUD only — no S3 access.
- **Cost-controlled by default.** DynamoDB on-demand billing, 90-day TTL on alerts, S3 lifecycle transitions to Infrequent Access (30d) and Glacier (90d).
- **Splunk is additive, never blocking.** Alerts go to Splunk only after the DynamoDB write succeeds, and a Splunk outage is logged but never fails a Lambda run. DynamoDB stays the source of truth.

---

## Detection rules

All alerts are tagged with the MITRE ATT&CK tactic and technique they correspond to.

| Rule | Log source | Logic | Tactic | Technique |
|---|---|---|---|---|
| `ssh_brute_force` | ssh | 5+ failed logins, same IP, 60s window | Credential Access | T1110.001 |
| `port_scan` | web | 10+ distinct paths probed, same IP, 60s window | Reconnaissance | T1046 |
| `windows_failed_logon_burst` | windows_event | 5+ Event ID 4625, same IP, 60s window | Credential Access | T1110 |
| `sql_injection_attempt` | web | SQLi pattern match on request path | Initial Access | T1190 |
| `directory_traversal` | web | Path traversal / sensitive file pattern match | Discovery | T1083 |

Rules 1–3 are **burst-detection** rules operating over a sliding time window. Rules 4–5 are **signature** rules that fire on a single matching event.

### Alert schema

```json
{
  "alert_id": "uuid",
  "timestamp": "ISO-8601",
  "rule_name": "ssh_brute_force",
  "log_type": "ssh",
  "source_ip": "185.220.101.45",
  "severity": "HIGH",
  "description": "8 failed SSH logins from 185.220.101.45 within 60s",
  "evidence": ["<raw log lines that triggered the rule>"],
  "mitre_attack": {
    "tactic": "Credential Access",
    "technique_id": "T1110.001",
    "technique_name": "Brute Force: Password Guessing"
  },
  "enriched": true,
  "threat_intel": {
    "verdict": "MALICIOUS",
    "virustotal": { "malicious": 17, "total_vendors": 91, "vt_link": "..." },
    "abuseipdb": { "confidence_score": 100, "is_tor": true, "country_code": "..." }
  },
  "ttl": 1234567890
}
```

---

## Threat intelligence enrichment

For every alert with a public source IP (private ranges are skipped to avoid wasting API quota), the enrichment Lambda queries VirusTotal and AbuseIPDB, then assigns a verdict and adjusts severity accordingly.

**Verdict**

| Condition | Verdict |
|---|---|
| AbuseIPDB ≥ 80% **or** VT malicious ≥ 10 | `MALICIOUS` |
| AbuseIPDB ≥ 50% **or** VT malicious ≥ 3 | `SUSPICIOUS` |
| otherwise | `CLEAN` |

**Severity escalation** — severity is only ever raised, never lowered:

| Condition | Minimum severity |
|---|---|
| AbuseIPDB ≥ 80% **or** VT malicious ≥ 5 | `HIGH` |
| AbuseIPDB ≥ 50% **or** Tor exit node | `MEDIUM` |

This is the difference between an alert that says *"8 failed logins from an IP"* and one that says *"8 failed logins from a Tor exit node flagged by 17 vendors with a 100% abuse confidence score"* — the second one tells an analyst what to do next.

---

## Splunk integration

Both Lambdas forward alerts to Splunk through the HTTP Event Collector, using a small shared client (`splunk_hec.py`, copied into each function directory because SAM packages each `CodeUri` separately).

**What gets sent**

| Sender | When | `source` | `time` | Event body |
|---|---|---|---|---|
| parser-detector | after the DynamoDB `put_item` | `cloud-siem:parser-detector` | alert `timestamp` | the alert, exactly as stored in DynamoDB |
| threat-intel | after the DynamoDB `update_item` | `cloud-siem:threat-intel` | `enriched_at` | the full alert merged with enrichment |

Detected alerts also carry the originating log file as the indexed field `s3_object` (for example `s3_object::s3://cloud-siem-logs-dev-<account>/security_logs.json`). Local test runs use `source=cloud-siem:local-test`. All events use `sourcetype=_json`, so Splunk extracts nested fields such as `mitre_attack.technique_id` and `threat_intel.verdict` automatically. Enriched events add `original_severity`, `severity_upgraded`, `enriched_at`, and the `threat_intel` block, and `severity` holds the upgraded value.

**Failure handling.** HEC errors and timeouts (5s) are logged, never raised. parser-detector sends alerts in batches of 100. threat-intel sends one event per enriched alert and stops trying Splunk for the rest of a run after the first failure, so an unreachable HEC can't add a timeout to every alert. Forwarding is skipped entirely when `HEC_URL` or `HEC_TOKEN` is empty.

**Configuration**

| Template parameter | Lambda env var | Default | Notes |
|---|---|---|---|
| `HecUrl` | `HEC_URL` | empty (disabled) | base URL such as `https://splunk.example.com:8088`; `/services/collector/event` is appended if missing |
| `HecToken` | `HEC_TOKEN` | empty (disabled) | `NoEcho: true`, entered at deploy time, never committed |
| `HecVerifySsl` | `HEC_VERIFY_SSL` | `true` | set `false` only for a self-signed local Splunk |

### Local Splunk for testing

```bash
docker run -d --name splunk -p 8000:8000 -p 8088:8088 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD='<choose-a-password>' \
  splunk/splunk:latest
```

In Splunk Web (http://localhost:8000): **Settings > Data Inputs > HTTP Event Collector > Global Settings**, enable all tokens, then **New Token** with source type `_json`. Verify the token without putting it in shell history:

```bash
read -s HECTOK
curl -k https://localhost:8088/services/collector/event \
  -H "Authorization: Splunk $HECTOK" -d '{"event":"hello"}'
# {"text":"Success","code":0}

sam build
sam local invoke ParserDetectorFunction -e event.json \
  --parameter-overrides "HecUrl=https://host.docker.internal:8088 HecToken=$HECTOK HecVerifySsl=false"
```

A deployed Lambda cannot reach Splunk on your laptop. For the AWS deployment, use an HEC endpoint reachable from the internet (for example a Splunk Cloud trial).

### Example searches

Each alert arrives twice with the same `alert_id`: once when detected and once when enriched. The enriched copy always has the later `_time`, so `dedup alert_id` keeps the most complete version.

```
# Alerts over time by severity
source="cloud-siem:*" | dedup alert_id | timechart count by severity

# Top attacking IPs
source="cloud-siem:*" | dedup alert_id | top limit=10 source_ip

# MITRE ATT&CK coverage
source="cloud-siem:*" | dedup alert_id
| stats count by mitre_attack.tactic, mitre_attack.technique_id, mitre_attack.technique_name

# Threat intel verdicts by country
source="cloud-siem:threat-intel" | dedup alert_id
| stats count by threat_intel.verdict, threat_intel.abuseipdb.country_code
```

---

## Log generator

`log_generator/logs.py` produces 300 synthetic log entries across three formats (SSH auth, Windows Event, web access), with realistic MITRE-tagged attacker behavior mixed into benign traffic.

**Key implementation detail:** attack traffic uses `generate_burst_timestamps()` to cluster related events 1–8 seconds apart, while benign traffic is scattered randomly across a 24-hour window. This matters — burst-detection rules operate over 60-second windows, so randomly distributed timestamps would mean a brute-force rule could never fire regardless of how many failed logins existed in the dataset.

```bash
cd log_generator && python logs.py
```

Outputs to `sample-logs/`: `security_logs.json` (combined) plus per-source files.

---

## How this maps to a production SOC

Every component here has a direct commercial equivalent. The stack is small, but the architecture is the same one Splunk ES, Microsoft Sentinel, and IBM QRadar implement at scale.

| Production SOC component | This project |
|---|---|
| Log shipper (Fluentd, Filebeat) | `log_generator/logs.py` |
| Log storage tier (S3, Elastic) | S3 bucket |
| SIEM parsing / normalization engine | parser-detector Lambda |
| Detection content (SPL, KQL, Sigma) | detection rules in `handler.py` |
| Threat intel platform (MISP, ThreatConnect) | threat-intel Lambda + VirusTotal + AbuseIPDB |
| Alert database | DynamoDB |
| Analyst console | Splunk dashboards, fed by HTTP Event Collector |
| ATT&CK coverage mapping | tags on every alert |

A SIEM is a process, not a product: **collect → normalize → enrich → correlate → alert → investigate.** The implementation is interchangeable; the pipeline is not.

### Detection methodology

Three approaches, in increasing order of sophistication:

- **Rule-based (signature)** — *if X occurs Y times in Z minutes, alert.* Fast and reliable against known techniques, blind to novel ones, noisy if poorly tuned. All five rules here are this type.
- **Threshold-based** — volume anomalies, e.g. outbound transfer exceeding 1 GB/hour. Catches exfiltration where individual events look unremarkable.
- **Behavioral (UEBA)** — baselines normal activity per user/entity, then alerts on deviation. Catches compromised accounts and insider threats that signatures miss, at the cost of a training period and higher false positives.

### ATT&CK coverage

Current rules cover the early kill chain. Later phases are the natural extension path:

| Phase | Covered | Techniques |
|---|---|---|
| Reconnaissance | ✅ | T1046 |
| Initial Access | ✅ | T1110.001, T1190 |
| Discovery | ✅ | T1083 |
| Credential Access | ✅ | T1110 |

---


## Deployment

**Prerequisites:** AWS account, AWS CLI (configured with an IAM user), AWS SAM CLI, Python 3.13, and free-tier API keys from [VirusTotal](https://www.virustotal.com) and [AbuseIPDB](https://www.abuseipdb.com).

```bash
sam build
sam deploy --guided
```

At the prompts, use a stack name with **hyphens only** (CloudFormation rejects underscores). API keys are declared with `NoEcho: true`, so they are entered interactively at deploy time and never written to `samconfig.toml`, the repo, or CloudFormation logs.

The Splunk parameters `HecUrl` and `HecToken` are optional. Leave them blank to deploy without Splunk forwarding; `HecToken` is also `NoEcho`. See [Splunk integration](#splunk-integration).

The stack outputs the generated bucket name, table name, and both function ARNs.

### Running the pipeline

```bash
# Upload logs — this triggers the parser Lambda automatically
aws s3api put-object \
  --bucket cloud-siem-logs-dev-<account-id> \
  --key security_logs.json \
  --body log_generator/sample-logs/security_logs.json

# Confirm alerts were written
aws dynamodb scan --table-name security-alerts-dev --select COUNT --no-cli-pager

# Threat-intel runs every 15 min on its own, or invoke it directly
aws lambda invoke --function-name siem-threat-intel-dev /tmp/out.json && cat /tmp/out.json

# Tail Lambda logs
aws logs tail /aws/lambda/siem-parser-detector-dev --since 10m
```

### Local development

Both handlers run standalone against a local DynamoDB container, no AWS calls required.

```bash
docker run -d -p 8000:8000 --name dynamodb-local amazon/dynamodb-local

aws dynamodb create-table \
  --table-name security-alerts \
  --attribute-definitions AttributeName=alert_id,AttributeType=S \
  --key-schema AttributeName=alert_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --endpoint-url http://localhost:8000
```

Set `LOCAL_MODE=true` plus your API keys in a `.env` file alongside each handler, then run the handlers directly with `python`.

To also send the parser-detector test run to Splunk, set `HEC_URL` (and `HEC_VERIFY_SSL=false` for a self-signed local Splunk). If `HEC_TOKEN` is not set, the script prompts for it without echoing:

```bash
HEC_URL=https://localhost:8088 HEC_VERIFY_SSL=false python lambda/parser-detector/handler.py
```

---

## Notes and gotchas

Things that cost real debugging time, recorded so they don't have to be rediscovered.

**`aws s3 cp` may hang on large uploads; `put-object` works.** Symptom: a 15-byte file uploads instantly, a 200 KB file times out with `[Errno 60] Operation timed out` — often with no error message at all, just a silent return and nothing in the bucket. Small packets fit inside the path MTU; large ones exceed it and are dropped without an ICMP response, so the connection hangs until timeout.

Ruled out along the way, in case the same symptom appears elsewhere: raw TLS connectivity to both the regional endpoint and the bucket subdomain was fine (`curl` returned normally); the problem reproduced on a cellular hotspot, eliminating the local network; and disabling all three macOS network extensions (Cisco Secure Client socket filter, ProtonVPN WireGuard and OpenVPN) changed nothing, eliminating VPN traffic interception. `--checksum-algorithm`, `AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED`, and reduced `multipart_chunksize` all failed too.

What works is `aws s3api put-object`, which issues one unchunked PUT instead of routing through the CLI's chunked transfer manager. Permanent fix is lowering MTU to 1400 on the active interface (`route get default` identifies it — it is not always `en0`).

**SAM resolves `CodeUri` relative to the template file, not the project root.** With the template at `infrastructure/template.yaml`, paths need a `../` prefix. Without it, SAM prints "Build Succeeded" while silently copying nothing.

**`sam local invoke` runs inside Docker, so `localhost` is the container.** To reach a Splunk running on the host, use `https://host.docker.internal:8088` as `HecUrl`. SAM local also only passes environment variables that are declared in the template, which is why `HEC_URL` and `HEC_TOKEN` are template parameters rather than ad-hoc env vars.

**CloudFormation names vs. env var names.** Stack names allow only letters, numbers, and hyphens, and template parameter names must be alphanumeric (`HecUrl`, not `HEC_URL`). Lambda environment variable names are not restricted this way, so `HEC_URL` is fine there.


