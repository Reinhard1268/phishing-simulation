# Phishing Incident Response Playbook
** Enterprise Phishing Simulation & Automated Defense**
**Version:** 2.0 | **Classification:** Internal Use Only

---

## Overview

This playbook defines the end-to-end incident response process for phishing incidents detected in the lab environment. It integrates with the toolchain from Projects 1–7: Wazuh (detection), TheHive 5 (case management), Shuffle SOAR (automation), and Elastic Stack (log analysis).

**Playbook Scope:** Phishing email delivery, link-click events, credential harvesting, and post-click endpoint activity.

---

## PHASE 1 — DETECTION (Automated)

### 1.1 Detection Sources

| Source | Rule/Query | Trigger Condition |
|--------|-----------|-------------------|
| Wazuh Rule 100800 | Phishing keyword in subject | Email subject contains urgency keywords |
| Wazuh Rule 100805 | User clicked phishing URL | Proxy log shows click on phishing domain |
| Wazuh Rule 100806 | Credential POST to external | HTTP POST with credentials to non-corp site |
| Wazuh Rule 100813 | SPF + DKIM both failed | Both auth checks fail on inbound email |
| Elastic PHQ-001 | Daily phishing click hunt | Scheduled KQL query fires on match |

### 1.2 Automated SOAR Response (Shuffle — Project 3 Integration)

When Wazuh fires rules 100805 or 100806, the following Shuffle workflow triggers automatically:

1. **Webhook received** from Wazuh alert via integration
2. **TheHive case created** with:
   - Title: `Phishing Click Detected — [username] — [timestamp]`
   - Severity: Medium (rule 100805) or High (rule 100806)
   - Tags: `phishing`, `user-click`, `simulation`
   - Observables: user email, clicked URL, source IP
3. **Slack notification sent** to `#soc-alerts` channel
4. **Email notification sent** to `soc@company.local`
5. **GoPhish API queried** to pull full campaign result for the triggering user

---

## PHASE 2 — TRIAGE (Analyst)

### 2.1 Verify the Incident is Real

Before escalating, confirm the alert is not a false positive:

- [ ] Open the TheHive case created by SOAR
- [ ] Confirm the triggering user exists in the target group (`target-groups.json`)
- [ ] Verify the phishing domain matches an active GoPhish campaign
- [ ] Check Elastic proxy logs: does the click timestamp match GoPhish campaign results?
- [ ] Confirm the user's IP address matches the expected internal subnet (192.168.1.0/24)

### 2.2 Severity Classification

| Severity | Criteria |
|----------|----------|
| **LOW** | Email received/opened, no click, no credential submission |
| **MEDIUM** | User clicked the phishing link but did not submit credentials |
| **HIGH** | User submitted credentials to the phishing landing page |
| **CRITICAL** | User submitted credentials AND stolen creds were used in subsequent auth events |

### 2.3 Notification Matrix

| Severity | Notify |
|----------|--------|
| LOW | Log in TheHive, no active notification |
| MEDIUM | SOC team lead via Slack |
| HIGH | SOC team lead + IT Manager via Slack + Email |
| CRITICAL | SOC team lead + IT Manager + CISO + Legal via all channels immediately |

---

## PHASE 3 — CONTAINMENT

### 3.1 Block Phishing URL at Proxy
```bash
# Run containment script
python3 ir-workflow/containment/containment-scripts.py \
  --action block_url \
  --url "http://phishing-lab.local" \
  --reason "Active phishing campaign R1-001" \
  --incident-id "INC-2024-001"
```

Expected outcome: URL added to Wazuh active response blocklist; all subsequent attempts by any user to access the URL are blocked and logged.

### 3.2 Block Sender Domain at Email Gateway
```bash
python3 ir-workflow/containment/containment-scripts.py \
  --action block_domain \
  --domain "phishing-domain.com" \
  --reason "Confirmed phishing sender" \
  --incident-id "INC-2024-001"
```

### 3.3 Identify All Recipients
```bash
python3 ir-workflow/containment/containment-scripts.py \
  --action identify_recipients \
  --campaign-id 1 \
  --incident-id "INC-2024-001"
```

Output: Full list of all users who received the phishing email, with click and submission status for each.

### 3.4 Scope Assessment

After running the above:
- [ ] List all users who received the email
- [ ] List all users who clicked the link
- [ ] List all users who submitted credentials
- [ ] For each credential submitter: run `check_credential_use` to detect if stolen creds were used

---

## PHASE 4 — INVESTIGATION

### 4.1 Email Header Analysis

For each phishing email received:
```bash
python3 ir-workflow/evidence-collection/email-header-analyzer.py \
  --input /path/to/phishing-email.eml
```

Investigate:
- [ ] Originating IP address and geolocation
- [ ] Mail server routing path (Received headers)
- [ ] SPF/DKIM/DMARC authentication results
- [ ] Reply-To vs From domain mismatch
- [ ] X-Originating-IP reputation check

### 4.2 URL Analysis

For the phishing URL:
- [ ] Run `email_parser.py` against the email
- [ ] Follow redirect chain manually or via script
- [ ] Check domain age (newly registered = high risk)
- [ ] VirusTotal URL reputation lookup
- [ ] Capture screenshot of landing page (for evidence)
- [ ] Check for credential harvesting code (view page source)

### 4.3 Credential Exposure Assessment

For each user who submitted credentials:
```bash
python3 ir-workflow/containment/containment-scripts.py \
  --action check_credential_use \
  --username "user@company.local" \
  --timestamp "2024-01-16T09:19:38Z" \
  --incident-id "INC-2024-001"
```

Look for:
- [ ] Authentication events within 30 minutes of credential submission
- [ ] Impossible travel (login from two geographically distant IPs)
- [ ] Successful logins from new/unusual IP addresses
- [ ] Access to sensitive systems or data after the credential capture time

### 4.4 Endpoint Investigation

For users who clicked the link (regardless of credential submission):
- [ ] Pull Sysmon logs for the endpoint (Wazuh + Elastic) — +/- 1 hour from click time
- [ ] Check for: new process creation, network connections, file downloads, registry changes
- [ ] If any executable was downloaded: submit to malware analysis pipeline (Project 7)
- [ ] Check for persistence mechanisms: scheduled tasks, registry run keys, startup folders

### 4.5 Lateral Movement Check

For HIGH/CRITICAL severity only:
- [ ] Check for authentication events from affected user to other internal systems
- [ ] Check for SMB/RDP/WMI connections originating from affected endpoint
- [ ] Review Zeek logs (Project 5) for unusual internal network traffic post-click

---

## PHASE 5 — REMEDIATION

### 5.1 Force Password Reset
```bash
python3 ir-workflow/containment/containment-scripts.py \
  --action force_password_reset \
  --username "user@company.local" \
  --incident-id "INC-2024-001"
```

In the lab, this logs the requirement and creates a TheHive task. In production, this would trigger the AD password reset API.

### 5.2 Revoke Active Sessions

- [ ] For cloud-connected accounts: revoke all OAuth tokens and active browser sessions
- [ ] For VPN users: terminate VPN session and re-authenticate
- [ ] For SSO-integrated apps: force re-authentication across all integrated apps

### 5.3 Scan Endpoints That Clicked Payload Links

- [ ] Trigger Wazuh SCA (Security Configuration Assessment) on affected endpoint
- [ ] Run Atomic Red Team test T1566 post-incident to validate detection
- [ ] If malware suspected: isolate endpoint and submit for full analysis (Project 7 pipeline)

### 5.4 Update Email Gateway Rules

- [ ] Add sending domain to permanent blocklist
- [ ] Add phishing subject line patterns to spam filter
- [ ] Update Wazuh rule 100800 with new keyword if a new pattern was used
- [ ] Add phishing URL to proxy blocklist (if not already done in Phase 3)

---

## PHASE 6 — POST-INCIDENT

### 6.1 TheHive Case Documentation

Required fields to complete in TheHive before closing:
- [ ] Full incident timeline (use evidence-collector.py output)
- [ ] Affected users list with impact level per user
- [ ] Root cause: which phishing template succeeded and why
- [ ] Detection gap analysis: why/how it reached the user
- [ ] Containment actions taken with timestamps
- [ ] Evidence bundle attached (run evidence-collector.py)

### 6.2 Lessons Learned

Within 48 hours of incident closure:
- [ ] Schedule brief post-incident review (15 min for LOW, 60 min for HIGH/CRITICAL)
- [ ] Document: what worked well, what failed, what to improve
- [ ] Update detection rules if a new technique bypassed existing rules
- [ ] Update this playbook if any step was missing or unclear

### 6.3 Detection Improvement Actions

| Gap Identified | Improvement Action | Owner | Deadline |
|---------------|-------------------|-------|----------|
| Rule missed new template | Add new keywords to rule 100800 | SOC Analyst | 48h |
| Proxy not logging POST body | Enable deep inspection | IT/Network | 1 week |
| Alert latency > 5 min | Tune Wazuh polling frequency | SOC Engineer | 3 days |

### 6.4 User Training Assignment

For users who clicked or submitted credentials:
- [ ] Assign mandatory phishing awareness training (user-training/materials/)
- [ ] Schedule follow-up targeted simulation within 30 days
- [ ] Track completion in awareness-metrics.json
- [ ] Report to HR/manager for HIGH/CRITICAL severity incidents per policy

---

## Playbook Maintenance

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 2.0 | 2026-01-15 | Amoah Reinhard | updated version |

**Review cycle:** After every phishing campaign and after any real phishing incident.
