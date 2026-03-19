# Phishing Incident Decision Tree
** Enterprise Phishing Simulation & Automated Defense**


## Decision Tree: Handling a Suspicious/Phishing Email Report
```
USER REPORTS SUSPICIOUS EMAIL
            │
            ▼
    ┌───────────────────────────────────────────────────┐
    │  STEP 1: INITIAL TRIAGE                           │
    │  Analyst reviews the reported email               │
    │  • Check sender domain vs display name            │
    │  • Check Reply-To vs From address                 │
    │  • Check SPF/DKIM/DMARC in headers                │
    │  • Run email through email_parser.py              │
    └──────────────────┬────────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │  Phishing Score ≥ 40?   │
          └────────┬────────┬───────┘
                   │ YES    │ NO
                   │        ▼
                   │   ┌─────────────────────────────┐
                   │   │ BENIGN / FALSE POSITIVE      │
                   │   │ • Log in TheHive as closed   │
                   │   │ • Thank reporter             │
                   │   │ • No further action          │
                   │   └─────────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────────────┐
    │  STEP 2: DETERMINE USER ACTION                   │
    │  Check GoPhish results + proxy logs              │
    └──────────────────┬───────────────────────────────┘
                       │
         ┌─────────────┼─────────────────┐
         │             │                 │
         ▼             ▼                 ▼
   ┌──────────┐  ┌──────────────┐  ┌───────────────────┐
   │ EMAIL    │  │ LINK         │  │ CREDENTIALS       │
   │ ONLY     │  │ CLICKED      │  │ SUBMITTED         │
   │ (opened/ │  │ (no creds    │  │                   │
   │  read)   │  │  submitted)  │  │                   │
   └────┬─────┘  └──────┬───────┘  └────────┬──────────┘
        │               │                    │
        ▼               ▼                    ▼
   ┌──────────┐   ┌────────────────┐   ┌─────────────────────────────┐
   │ LOW      │   │ MEDIUM         │   │ HIGH SEVERITY               │
   │          │   │                │   │                             │
   │ Actions: │   │ Actions:       │   │ Actions:                    │
   │ • Log    │   │ • Create       │   │ • IMMEDIATELY notify SOC    │
   │   TheHive│   │   TheHive case │   │   lead + IT Manager         │
   │ • No     │   │ • Notify SOC   │   │ • Force password reset NOW  │
   │   notif. │   │   team lead    │   │ • Revoke all sessions       │
   │ • Add to │   │ • Block URL    │   │ • Block URL + sender domain │
   │   metrics│   │ • Block sender │   │ • Check for credential USE  │
   └──────────┘   │ • Assign user  │   │ • Endpoint investigation    │
                  │   training     │   │ • Lateral movement check    │
                  │ • Collect      │   │ • Collect full evidence     │
                  │   evidence     │   │ • Assign mandatory training │
                  └────────────────┘   └─────────────────┬───────────┘
                                                         │
                                       ┌─────────────────▼───────────────┐
                                       │  STEP 3: STOLEN CREDS USED?     │
                                       │  Run check_credential_use()     │
                                       │  Check Elastic auth logs        │
                                       └─────────────┬─────────┬─────────┘
                                                     │         │
                                                  NO │         │ YES
                                                     ▼         ▼
                                              ┌──────────┐  ┌──────────────────────────┐
                                              │ HIGH     │  │ CRITICAL                 │
                                              │ Proceed  │  │                          │
                                              │ with HIGH│  │ • Escalate to CISO       │
                                              │ playbook │  │ • Notify Legal           │
                                              └──────────┘  │ • Isolate endpoint       │
                                                            │ • Full forensic image    │
                                                            │ • Check for data         │
                                                            │   exfiltration           │
                                                            │ • Preserve evidence      │
                                                            │   chain of custody       │
                                                            │ • Consider breach        │
                                                            │   notification review    │
                                                            └──────────────────────────┘
```

---

## Decision Tree: Attachment Clicked / Executable Downloaded
```
USER REPORTS OR SYSTEM DETECTS: Executable downloaded via email link
            │
            ▼
    ┌───────────────────────────────────────┐
    │  IMMEDIATE ISOLATION                  │
    │  • Disconnect endpoint from network   │
    │  • Do NOT reboot (preserve memory)    │
    │  • Alert SOC team immediately         │
    └───────────────────┬───────────────────┘
                        │
                        ▼
    ┌───────────────────────────────────────┐
    │  COLLECT ARTIFACTS                    │
    │  • Hash the file (MD5/SHA256)          │
    │  • Memory dump (if possible)          │
    │  • Sysmon logs from Wazuh/Elastic     │
    │  • Network connections at time of exec │
    └───────────────────┬───────────────────┘
                        │
                        ▼
    ┌───────────────────────────────────────┐
    │  SUBMIT TO MALWARE PIPELINE           │
    │  (Project 07 — Malware Analysis)      │
    │  • Static: YARA, strings, hashes      │
    │  • Dynamic: Cuckoo sandbox            │
    │  • IOC extraction                     │
    └───────────────────┬───────────────────┘
                        │
          ┌─────────────▼─────────────┐
          │  Malicious confirmed?      │
          └─────────┬─────────┬───────┘
                    │ YES     │ NO (FP)
                    │         ▼
                    │    ┌────────────────────┐
                    │    │ Document, release  │
                    │    │ endpoint, close    │
                    │    └────────────────────┘
                    ▼
    ┌───────────────────────────────────────┐
    │  REMEDIATE                            │
    │  • Wipe and reimage endpoint          │
    │  • Reset all credentials on endpoint  │
    │  • Deploy updated YARA rules to SIEM  │
    │  • Add IOCs to blocklists             │
    │  • Full post-incident review          │
    └───────────────────────────────────────┘
```

---

## Quick Reference: Severity → Action Matrix

| Condition | Severity | Password Reset | Session Revoke | Endpoint Isolate | CISO Notify |
|-----------|----------|---------------|----------------|-----------------|-------------|
| Email opened only | LOW | No | No | No | No |
| Link clicked | MEDIUM | No | No | No | No |
| Creds submitted | HIGH | **YES** | **YES** | No | No |
| Creds used | CRITICAL | **YES** | **YES** | **YES** | **YES** |
| Executable run | CRITICAL | **YES** | **YES** | **YES** | **YES** |
