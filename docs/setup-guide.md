# Setup Guide: Enterprise Phishing Simulation & Automated Defense
**Author:** Amoah Reinhard
---

## Prerequisites

- Kali Linux (tested on 2024.x) with 32GB RAM
- Docker and Docker Compose installed
- Python 3.11+
- Projects 01–07 stack running (Wazuh, Elastic, TheHive, Shuffle)
- Internet access for initial package installation

---

## Step 1: Install GoPhish on Kali Linux
```bash
# Download the latest GoPhish release
cd /opt
wget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip -d gophish
cd gophish

# Make the binary executable
chmod +x gophish

# Edit config.json to set the admin listen address
# Default admin port is 3333, phishing server port is 80
# For the lab, we use 127.0.0.1 for admin and 0.0.0.0 for the listener
nano config.json
```

**config.json for lab:**
```json
{
  "admin_server": {
    "listen_url": "127.0.0.1:3333",
    "use_tls": false,
    "cert_path": "",
    "key_path": ""
  },
  "phish_server": {
    "listen_url": "0.0.0.0:8080",
    "use_tls": false,
    "cert_path": "",
    "key_path": ""
  },
  "db_name": "sqlite3",
  "db_path": "gophish.db",
  "migrations_prefix": "db/db_",
  "contact_address": "",
  "logging": {
    "filename": "",
    "level": ""
  }
}
```
```bash
# Start GoPhish
sudo ./gophish

# You will see the admin password printed on first run — SAVE IT
# Example: time="..." msg="Please login with the username admin and the password [GENERATED_PASSWORD]"

# Access GoPhish admin at http://localhost:3333
# Default login: admin / [generated password shown in terminal]
```

---

## Step 2: Install MailHog (Local SMTP for Lab)

MailHog is a fake SMTP server that captures all outgoing emails for the lab — no real emails are sent.
```bash
# Option 1: Docker (recommended)
docker run -d \
  --name mailhog \
  -p 1025:1025 \
  -p 8025:8025 \
  mailhog/mailhog

# Verify MailHog is running
curl http://localhost:8025
# You should see the MailHog web UI response

# Option 2: Direct binary
wget https://github.com/mailhog/MailHog/releases/latest/download/MailHog_linux_amd64
chmod +x MailHog_linux_amd64
./MailHog_linux_amd64 &

# MailHog web UI: http://localhost:8025
# SMTP listener: localhost:1025
```

---

## Step 3: Configure GoPhish

### 3.1 Get the API Key
```bash
# After logging in at http://localhost:3333
# Go to: Settings → API Key → Copy
# Add to your .env file as GOPHISH_API_KEY
```

### 3.2 Create the SMTP Profile

In the GoPhish admin UI:
1. Navigate to **Sending Profiles**
2. Click **+ New Profile**
3. Enter the values from `gophish/campaigns/smtp-profile.json`
4. Click **Send Test Email** to verify MailHog receives it
5. Save the profile

### 3.3 Import Email Templates

For each file in `gophish/templates/`:
1. Navigate to **Email Templates**
2. Click **+ New Template**
3. Copy the `name`, `subject`, `html`, and `text` fields from the JSON
4. Enable **Capture Credentials** if specified in the JSON
5. Set the redirect URL from the JSON
6. Save

### 3.4 Import Landing Pages

For each file in `gophish/landing-pages/`:
1. Navigate to **Landing Pages**
2. Click **+ New Page**
3. Set the name and paste the HTML content
4. Enable **Capture Submitted Data** and **Capture Passwords**
5. Set the redirect URL
6. Save

### 3.5 Create the Target Group

1. Navigate to **Users & Groups**
2. Click **+ New Group**
3. Name it `lab-users`
4. Add the 10 users from `gophish/campaigns/target-groups.json`
5. Save

---

## Step 4: Configure the .env File
```bash
# Copy the example file
cp .env.example .env

# Edit with your actual values
nano .env

# Required values to fill in:
# GOPHISH_API_KEY - from GoPhish Settings page
# ELASTIC_PASSWORD - from your Project 01 setup
# WAZUH_PASSWORD - from your Project 01 setup
# THEHIVE_API_KEY - from TheHive Settings
# SLACK_WEBHOOK_URL - from your Slack app (optional but recommended)
```

---

## Step 5: Install Python Dependencies
```bash
# From the project root directory
pip install -r requirements.txt --break-system-packages

# Verify key packages
python3 -c "import gophish; print('OK')" 2>/dev/null || echo "Note: no gophish SDK needed, using requests"
python3 -c "import rich; print('rich OK')"
python3 -c "import elasticsearch; print('elasticsearch OK')"
python3 -c "import reportlab; print('reportlab OK')"
```

---

## Step 6: Run Your First Campaign (Dry Run)
```bash
# Always do a dry run first to verify config
python3 scripts/campaign-launcher.py \
  --config gophish/campaigns/campaign-round1-config.json \
  --dry-run

# Review the output — verify:
# - SMTP profile is accessible
# - Landing page exists in GoPhish
# - Target group exists with correct number of targets
```

---

## Step 7: Launch the Campaign
```bash
# Launch Round 1 campaign
python3 scripts/campaign-launcher.py \
  --config gophish/campaigns/campaign-round1-config.json

# Optional: delay launch by 10 minutes
python3 scripts/campaign-launcher.py \
  --config gophish/campaigns/campaign-round1-config.json \
  --delay-minutes 10

# The script will:
# 1. Run pre-flight checks
# 2. Launch the campaign via GoPhish API
# 3. Monitor progress every 60 seconds (live stats table)
# 4. Save results to gophish/results/
# 5. Send Slack notification when complete
# 6. Trigger log-collector.py automatically
```

---

## Step 8: Monitor the Campaign in Real Time

The launcher script provides live stats. You can also monitor in:

- **GoPhish Admin UI**: http://localhost:3333 → Campaigns → View Results
- **MailHog UI**: http://localhost:8025 — see all captured emails
- **Kibana**: http://localhost:5601 — proxy and email gateway logs
- **Wazuh Dashboard**: http://localhost:5601 (or dedicated Wazuh Kibana) — phishing alerts

---

## Step 9: Collect Results with log-collector.py
```bash
# After campaign completes (or during, for live collection)
python3 scripts/log-collector.py \
  --campaign-id 1 \
  --output-dir gophish/results

# This collects from:
# - GoPhish API (campaign results)
# - Elasticsearch (proxy + email logs)
# - Wazuh (phishing alerts)
# Outputs: raw-results-1.json, timeline-1.json, user-activity-1.json
```

---

## Step 10: Generate the Report
```bash
# Generate PDF and Markdown report for Round 1
python3 scripts/report-generator.py \
  --campaign-id 1 \
  --round 1 \
  --format both

# Output files:
# metrics/campaign-stats/campaign-report-round1.pdf
# metrics/campaign-stats/campaign-report-round1.md

# Generate click-rate charts
python3 metrics/click-rates/click-rate-chart.py
# Charts saved to: metrics/click-rates/charts/
```

---

## Step 11: Set Up Wazuh Detection Rules
```bash
# Copy phishing detection rules to Wazuh
sudo cp detection/wazuh-rules/phishing-detection-rules.xml \
  /var/ossec/etc/rules/local_phishing_rules.xml

# Copy email gateway decoder
sudo cp detection/wazuh-rules/email-gateway-decoder.xml \
  /var/ossec/etc/decoders/email_gateway_decoder.xml

# Validate the rules
sudo /var/ossec/bin/ossec-logtest

# Restart Wazuh manager to load new rules
sudo systemctl restart wazuh-manager

# Verify rules loaded
sudo grep -r "100800" /var/ossec/etc/rules/
```

---

## Step 12: Import Kibana Queries
```bash
# The hunting queries are in detection/elastic-queries/phishing-hunting-queries.json
# Import via Kibana:
# 1. Open Kibana → Stack Management → Saved Objects
# 2. Import → Upload phishing-hunting-queries.json
# OR use them directly in Kibana Discover with the KQL strings from the JSON
```

---

## Troubleshooting

**GoPhish won't start:**
```bash
sudo lsof -i :3333  # Check if port is in use
sudo lsof -i :8080
sudo ./gophish 2>&1 | head -50  # Check error output
```

**MailHog not receiving emails:**
```bash
docker ps | grep mailhog  # Verify container is running
curl -s http://localhost:8025/api/v2/messages | python3 -m json.tool
# If no messages, verify GoPhish SMTP profile points to localhost:1025
```

**GoPhish API returns 401:**
```bash
# Regenerate API key in GoPhish UI: Settings → API Key → Reset
# Update GOPHISH_API_KEY in .env
```

**Elasticsearch connection refused:**
```bash
curl http://localhost:9200  # Test basic connectivity
# If Project 01 stack not running: cd /path/to/project01 && docker-compose up -d
```

**Python package import errors:**
```bash
pip install -r requirements.txt --break-system-packages --upgrade
python3 -c "import rich, elasticsearch, reportlab; print('All OK')"
```
