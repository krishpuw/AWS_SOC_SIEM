# Cloud-Native SIEM Pipeline

A serverless SIEM built on AWS that ingests security logs, detects threats using
MITRE ATT&CK-mapped rules, enriches alerts with live threat intelligence, and
forwards everything to Splunk for real-time dashboarding.

## Architecture

Deployed on AWS via SAM/CloudFormation. Splunk Enterprise self-hosted on EC2.

## Dashboard

![SOC Dashboard](images/dashboard.png)

## Detection Rules

| Rule | Source | Logic | MITRE Tactic |
|---|---|---|---|
| `ssh_brute_force` | ssh | 5+ failed logins, same IP, 60s | Credential Access |
| `port_scan` | web | 10+ distinct paths, same IP, 60s | Reconnaissance |
| `windows_failed_logon_burst` | windows | 5+ failed logons (4625), 60s | Credential Access |
| `sql_injection_attempt` | web | SQLi pattern match | Initial Access |
| `directory_traversal` | web | Path traversal pattern match | Discovery |

## Threat Intel Enrichment

Every alert with a public IP is checked against VirusTotal and AbuseIPDB.
Severity is escalated (never lowered) based on the results — e.g. an SSH
brute-force alert from a Tor exit node with a 100% abuse score gets flagged
`HIGH` automatically, no analyst lookup required.

## AWS Infrastructure

![Lambda Functions](images/lambda-functions.png)
![EC2 Instance](images/ec2-instance.png)
![Security Group](images/security-group.png)

Both Lambdas forward every alert to Splunk via HTTP Event Collector, in
addition to writing to DynamoDB. Splunk forwarding is non-blocking — a
Splunk outage is logged but never fails a detection run.

## Pipeline Verification

![CloudWatch Logs](images/cloudwatch-logs.png)

## Tech Stack

AWS Lambda · S3 · DynamoDB · SAM/CloudFormation · EC2 · Splunk Enterprise ·
Python · VirusTotal API · AbuseIPDB API

## Setup

```bash
sam build
sam deploy --guided
```

Requires AWS CLI, SAM CLI, Python 3.13, and free-tier API keys from
VirusTotal and AbuseIPDB. Splunk HEC URL/token are optional deploy
parameters — leave blank to run without Splunk forwarding.
