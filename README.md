# Enterprise Phishing Simulation & Automated Defense
> **Platform:** Kali Linux · 32GB RAM · Docker

---

## ⚠️ Ethical Notice

All phishing simulations in this project are conducted exclusively in an **isolated lab environment**. No real users are targeted. All email addresses are fictional and use the `company.local` domain. This project is purely educational and for portfolio demonstration purposes. Phishing attacks against real individuals without explicit written authorization are illegal.

---

## Overview

This project builds a complete enterprise-grade phishing simulation and automated defense pipeline. It covers the full attack-and-defend lifecycle:

1. **Simulate** — Realistic multi-round phishing campaigns using GoPhish and MailHog
2. **Detect** — Custom Wazuh rules and Elastic KQL hunting queries that fire on phishing events
3. **Respond** — Automated IR playbooks, evidence collection, and SOAR-driven containment
4. **Train** — Interactive HTML awareness module, quiz, and awareness metrics tracking
5. **Measure** — Before/after metrics across 3 campaign rounds showing quantifiable improvement

Three campaign rounds were run against a 10-user lab group:

| Round | Condition | Click Rate | Submission Rate | Report Rate |
|-------|-----------|-----------|----------------|------------|
| 1 | No training | 70% | 40% | 10% |
| 2 | Post-training | 30% | 10% | 40% |
| 3 | Tuned defenses | 10% | 0% | 60% |

---

## Stack & Integrations

| Tool | Role | Endpoint |
|------|------|----------|
| **GoPhish** | Phishing campaign engine | `localhost:3333` |
| **MailHog** | Local SMTP capture (no real emails) | `localhost:1025 / 8025` |
| **Wazuh 4.x** | SIEM — phishing detection rules | `localhost:55000` |
| **Elasticsearch 8.x** | Log storage + KQL hunting | `localhost:9200` |
| **Kibana** | Dashboards + query interface | `localhost:5601` |
| **TheHive 5** | Case management | `localhost:9000` |
| **Shuffle SOAR** | Automated response workflows | `localhost:3001` |


---

## Project Structure
```
phishing-simulation/
├── gophish/
│   ├── campaigns/          # GoPhish campaign configs (3 rounds)
│   ├── templates/          # 5 phishing email templates (JSON)
│   ├── landing-pages/      # 5 credential-capture landing pages (HTML)
│   └── results/            # Exported campaign results (JSON)
├── detection/
│   ├── wazuh-rules/        # 16 custom Wazuh detection rules + email decoder
│   ├── elastic-queries/    # 10 KQL hunting queries
│   └── email-parser/       # Phishing email parser + scorer (Python)
├── ir-workflow/
│   ├── playbook/           # 6-phase IR playbook + ASCII decision tree
│   ├── evidence-collection/# Evidence collector + email header analyzer
│   └── containment/        # URL/domain blocker + credential use checker
├── user-training/
│   ├── materials/          # Awareness guide + 10-question quiz (Markdown)
│   ├── mock-training/      # Standalone interactive HTML training module
│   └── awareness-metrics/  # Pre/post training metrics + analysis
├── metrics/
│   ├── campaign-stats/     # 3-round comparison JSON + Markdown report
│   ├── click-rates/        # Click rate tracker + matplotlib chart generator
│   └── before-after/       # Defense improvement report (86% risk reduction)
├── scripts/
│   ├── campaign-launcher.py    # Launch + monitor GoPhish campaigns
│   ├── log-collector.py        # Correlate GoPhish + Elastic + Wazuh logs
│   └── report-generator.py     # Generate PDF + Markdown campaign reports
├── docs/
│   ├── setup-guide.md          # Full installation and configuration guide
│   └── lessons-learned.md      # Post-campaign analysis and recommendations
├── .env.example
└── requirements.txt
```

---

## Phishing Templates

Five realistic templates covering the most dangerous social engineering themes:

| # | Template | Theme | Round 1 Click Rate |
|---|----------|-------|-------------------|
| 1 | `office365-mfa-template.json` | Microsoft MFA update required | 70% |
| 2 | `it-password-expiry-template.json` | Network password expires in 24h | 30% |
| 3 | `hr-benefits-template.json` | Benefits enrollment closing | 10% |
| 4 | `ceo-wire-transfer-template.json` | CEO BEC wire transfer request | — |
| 5 | `parcel-delivery-template.json` | Canada Post failed delivery | — |

---

## Detection Rules

**16 custom Wazuh rules** (IDs 100800–100816) covering:

- Suspicious urgency keywords in email subject
- External sender to internal recipient (spear-phishing indicator)
- Emails with executable attachments
- Email links pointing to raw IP addresses
- Sender display name vs. actual domain mismatch
- Proxy log: user clicked phishing URL
- Proxy log: credential POST to external non-corporate site
- Mass click on same URL (3+ users within 5 minutes)
- High email volume from single new external sender
- URL shorteners in email links
- SPF / DKIM / DMARC authentication failures
- GoPhish simulation tracking events (lab-specific)

**10 KQL hunting queries** for Elastic/Kibana covering:
- Users who clicked phishing links today
- Credential submissions to external sites
- Email links to IP addresses
- Executable downloads via email
- Multiple users accessing same suspicious URL
- After-hours email link clicks
- New domains first seen in email traffic
- Suspicious TLD detection (.xyz, .tk, .ml, etc.)

---

## Scripts

### campaign-launcher.py
```bash
# Dry run (verify config without launching)
python3 scripts/campaign-launcher.py \
  --config gophish/campaigns/campaign-round1-config.json \
  --dry-run

# Live launch with 5-minute delay
python3 scripts/campaign-launcher.py \
  --config gophish/campaigns/campaign-round1-config.json \
  --delay-minutes 5
```

Performs pre-flight checks (SMTP, landing page, target group), launches the campaign, monitors live stats in a rich terminal table (refreshes every 60s), saves results, and sends a Slack notification on completion.

### log-collector.py
```bash
python3 scripts/log-collector.py \
  --campaign-id 1 \
  --output-dir gophish/results
```

Collects from GoPhish API, Elasticsearch (proxy + email logs), and Wazuh alerts. Correlates all events by user and timestamp, builds a unified timeline, and saves `raw-results.json`, `timeline.json`, and `user-activity.json`.

### report-generator.py
```bash
# Generate PDF + Markdown report for Round 1
python3 scripts/report-generator.py \
  --campaign-id 1 \
  --round 1 \
  --format both
```

Generates a full PDF report with cover page, executive summary, results dashboard, matplotlib charts, per-template breakdown, detection performance, and recommendations. Also outputs a Markdown version.

### click-rate-chart.py
```bash
python3 metrics/click-rates/click-rate-chart.py
```

Generates 4 matplotlib charts: click rate trend line, template effectiveness bar chart, hour-of-day click distribution, and submission vs. click rate comparison. Embeds all charts into a PDF summary.

---

## IR Workflow

The `ir-workflow/` directory contains the complete incident response toolkit:
```bash
# Block a phishing URL
python3 ir-workflow/containment/containment-scripts.py \
  --action block_url \
  --url "http://phishing-lab.local" \
  --reason "Active campaign R1" \
  --incident-id "INC-2024-001"

# Identify all recipients of a campaign
python3 ir-workflow/containment/containment-scripts.py \
  --action identify_recipients \
  --campaign-id 1 \
  --incident-id "INC-2024-001"

# Check if stolen credentials were used post-submission
python3 ir-workflow/containment/containment-scripts.py \
  --action check_credential_use \
  --username "james.oduya@company.local" \
  --timestamp "2024-01-16T09:19:38Z" \
  --incident-id "INC-2024-001"

# Collect full evidence bundle for a specific user
python3 ir-workflow/evidence-collection/evidence-collector.py \
  --campaign-id 1 \
  --user-email "james.oduya@company.local" \
  --incident-id "INC-2024-001" \
  --output-dir ir-workflow/evidence-collection/bundles

# Analyze email headers for spoofing indicators
python3 ir-workflow/evidence-collection/email-header-analyzer.py \
  --input /path/to/phishing-email.eml
```

---

## User Training

The `user-training/` directory contains:

- **`phishing-awareness-guide.md`** — Complete user-facing awareness document with 10 warning signs, real vs. fake examples, and a quick reference card
- **`phishing-quiz.md`** — 10 multiple-choice questions with explained answers and scoring guide
- **`training-module.html`** — Fully self-contained interactive training module (no dependencies). Open in any browser. Includes 4 sections, 5 interactive quiz questions, progress tracking, pass/fail scoring (≥80%), and a printable completion certificate

To open the training module:
```bash
firefox user-training/mock-training/training-module.html
```

---

## Wazuh Rule Deployment
```bash
# Deploy phishing detection rules
sudo cp detection/wazuh-rules/phishing-detection-rules.xml \
  /var/ossec/etc/rules/local_phishing_rules.xml

# Deploy email gateway decoder
sudo cp detection/wazuh-rules/email-gateway-decoder.xml \
  /var/ossec/etc/decoders/email_gateway_decoder.xml

# Validate and reload
sudo /var/ossec/bin/ossec-logtest
sudo systemctl restart wazuh-manager
```

---

## Installation
```bash
# Clone the repo
git clone https://github.com/Reinhard1268/phishing-simulation.git
cd phishing-simulation

# Install Python dependencies
pip install -r requirements.txt --break-system-packages

# Configure environment
cp .env.example .env
nano .env  # Fill in your GoPhish API key, Elastic password, etc.

# Verify GoPhish is running
curl -s http://localhost:3333 | head -5

# Verify MailHog is running
curl -s http://localhost:8025 | head -5
```

See `docs/setup-guide.md` for the full step-by-step installation and configuration walkthrough.

---

## Key Results

| Metric | Round 1 → Round 3 | Improvement |
|--------|-------------------|-------------|
| Click rate | 70% → 10% | **↓ 85.7%** |
| Credential submission | 40% → 0% | **↓ 100%** |
| Reporting rate | 10% → 60% | **↑ 500%** |
| SIEM detection accuracy | 40% → 92% | **↑ 130%** |
| Mean time to detect | 47 min → 3 min | **↓ 93.6%** |
| Composite risk score | 0.57 → 0.08 | **↓ 86%** |

Full analysis: [`metrics/before-after/defense-improvement-report.md`](metrics/before-after/defense-improvement-report.md)

---

## Portfolio Context

| # | Project | Status |
|---|---------|--------|
| 01 | HomeSOC-Enterprise (Wazuh + Elastic + TheHive + SOAR) | ✅ |
| 02 | Detection Engineering (25 Sigma rules + converters) | ✅ |
| 03 | SOAR Automation (FastAPI + 5 playbooks) | ✅ |
| 04 | Threat Hunting Platform (Sysmon + KQL + playbook) | ✅ |
| 05 | Zeek NSM (6 scripts + 41 Suricata rules + ML) | ✅ |
| 06 | Cloud SOC Canada (AWS + Azure + PIPEDA) | ✅ |
| 07 | Malware Analysis Pipeline (Cuckoo + YARA + reports) | ✅ |
| **08** | **Enterprise Phishing Simulation (this repo)** | ✅ |
| 09 | TBD | 🔄 |
| 10 | TBD | 🔄 |

---

## License

This project is for educational and portfolio purposes only. All phishing templates, landing pages, and simulation scripts are to be used exclusively in authorized lab environments. Unauthorized use against real individuals or systems is illegal.
