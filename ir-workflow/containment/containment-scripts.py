#  Enterprise Phishing Simulation & Automated Defense
# Containment actions: block URLs, block domains, identify recipients, check credential use

import argparse
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()
console = Console()

GOPHISH_URL = os.getenv("GOPHISH_URL", "http://localhost:3333")
GOPHISH_API_KEY = os.getenv("GOPHISH_API_KEY", "")
WAZUH_URL = os.getenv("WAZUH_URL", "http://localhost:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")

AUDIT_LOG = Path("ir-workflow/containment/containment-audit.log")
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)


def log_action(action: str, details: dict, incident_id: str) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "action": action,
        "details": details,
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    console.print(f"[dim]Audit logged: {action}[/dim]")


def get_wazuh_token() -> str:
    try:
        resp = requests.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            verify=False, timeout=10
        )
        return resp.json().get("data", {}).get("token", "")
    except Exception as e:
        console.print(f"[yellow]Wazuh auth failed: {e}[/yellow]")
        return ""


def get_thehive_headers() -> dict:
    return {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }


def create_thehive_task(incident_id: str, title: str, description: str) -> bool:
    try:
        headers = get_thehive_headers()
        case_resp = requests.get(
            f"{THEHIVE_URL}/api/case?q=title:{incident_id}",
            headers=headers, timeout=10
        )
        cases = case_resp.json()
        if isinstance(cases, list) and len(cases) > 0:
            case_id = cases[0]["id"]
            task_payload = {
                "title": title,
                "description": description,
                "status": "Waiting",
                "flag": False,
            }
            resp = requests.post(
                f"{THEHIVE_URL}/api/case/{case_id}/task",
                headers=headers, json=task_payload, timeout=10
            )
            if resp.status_code in (200, 201):
                console.print(f"[green]TheHive task created: {title}[/green]")
                return True
        console.print(f"[yellow]TheHive case {incident_id} not found — task not created[/yellow]")
        return False
    except Exception as e:
        console.print(f"[yellow]TheHive task creation failed: {e}[/yellow]")
        return False


def block_url_in_proxy(url: str, reason: str, incident_id: str) -> dict:
    console.print(Panel(
        f"[bold red]ACTION: Block URL in Proxy[/bold red]\n"
        f"URL: {url}\nReason: {reason}",
        expand=False
    ))

    result = {
        "action": "block_url",
        "url": url,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "steps": []
    }

    # Add to Wazuh CDB blocklist
    token = get_wazuh_token()
    if token:
        try:
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            cdb_entry = {"key": url, "value": f"phishing:{reason}:{incident_id}"}
            resp = requests.put(
                f"{WAZUH_URL}/lists/files/phishing_blocked_urls",
                headers=headers,
                json=[cdb_entry],
                verify=False, timeout=10
            )
            if resp.status_code in (200, 201):
                result["steps"].append({"step": "wazuh_cdb", "status": "success"})
                console.print("[green]  ✓ URL added to Wazuh CDB blocklist[/green]")
                # Reload CDB
                requests.put(f"{WAZUH_URL}/manager/configuration/validation", headers=headers, verify=False, timeout=5)
            else:
                result["steps"].append({"step": "wazuh_cdb", "status": "failed", "http": resp.status_code})
                console.print(f"[yellow]  ✗ Wazuh CDB update returned {resp.status_code}[/yellow]")
        except Exception as e:
            result["steps"].append({"step": "wazuh_cdb", "status": "error", "error": str(e)})
    else:
        result["steps"].append({"step": "wazuh_cdb", "status": "skipped_no_token"})

    # Create TheHive task for verification
    create_thehive_task(
        incident_id,
        f"Verify URL block: {url[:50]}",
        f"Verify that URL {url} is blocked at the proxy level.\nReason: {reason}\nTimestamp: {result['timestamp']}"
    )

    result["status"] = "completed"
    log_action("block_url", result, incident_id)
    console.print(f"[bold green]URL block action completed for: {url}[/bold green]")
    return result


def block_sender_domain(domain: str, reason: str, incident_id: str) -> dict:
    console.print(Panel(
        f"[bold red]ACTION: Block Sender Domain[/bold red]\n"
        f"Domain: {domain}\nReason: {reason}",
        expand=False
    ))

    result = {
        "action": "block_domain",
        "domain": domain,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "steps": []
    }

    # Build a Wazuh local rule to block this sender domain
    rule_xml = f"""<!-- Auto-generated by containment-scripts.py | Incident: {incident_id} -->
<group name="phishing,blocked_domain,">
  <rule id="199001" level="14">
    <decoded_as>email-gateway</decoded_as>
    <field name="email.from_domain">{domain}</field>
    <description>BLOCKED: Email from blocked phishing domain: {domain} | Incident: {incident_id}</description>
    <group>phishing,blocked_sender,auto_response,</group>
  </rule>
</group>"""

    rule_path = Path(f"ir-workflow/containment/blocked-domain-rules/block-{domain.replace('.', '-')}.xml")
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(rule_xml)
    result["steps"].append({"step": "rule_file_created", "status": "success", "path": str(rule_path)})
    console.print(f"[green]  ✓ Wazuh rule file created: {rule_path}[/green]")
    console.print(f"[dim]  → Deploy rule to /var/ossec/etc/rules/ on Wazuh manager[/dim]")

    create_thehive_task(
        incident_id,
        f"Deploy domain block rule: {domain}",
        f"Deploy rule file {rule_path} to Wazuh manager.\nDomain: {domain}\nReason: {reason}\nBlock timestamp: {result['timestamp']}"
    )

    result["status"] = "completed"
    log_action("block_domain", result, incident_id)
    console.print(f"[bold green]Domain block action completed for: {domain}[/bold green]")
    return result


def identify_all_recipients(campaign_id: int, incident_id: str) -> dict:
    console.print(Panel(
        f"[bold cyan]ACTION: Identify All Campaign Recipients[/bold cyan]\n"
        f"Campaign ID: {campaign_id}",
        expand=False
    ))

    try:
        resp = requests.get(
            f"{GOPHISH_URL}/api/campaigns/{campaign_id}/results",
            headers={"Authorization": f"Bearer {GOPHISH_API_KEY}"},
            verify=False, timeout=10
        )
        resp.raise_for_status()
        campaign_data = resp.json()
    except Exception as e:
        console.print(f"[red]Failed to fetch campaign results: {e}[/red]")
        return {"error": str(e)}

    recipients = []
    for r in campaign_data.get("results", []):
        recipients.append({
            "email": r.get("email"),
            "first_name": r.get("first_name"),
            "last_name": r.get("last_name"),
            "position": r.get("position"),
            "status": r.get("status"),
            "clicked": r.get("click_date") is not None,
            "submitted_credentials": r.get("submit_date") is not None,
            "reported": r.get("reported", False),
            "click_date": r.get("click_date"),
            "submit_date": r.get("submit_date"),
        })

    table = Table(title=f"Campaign {campaign_id} — All Recipients")
    table.add_column("Email", style="cyan")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Clicked", justify="center")
    table.add_column("Creds Submitted", justify="center")
    table.add_column("Reported", justify="center")

    for r in recipients:
        status_color = "red" if r["submitted_credentials"] else ("yellow" if r["clicked"] else "green")
        table.add_row(
            r["email"],
            f"{r['first_name']} {r['last_name']}",
            f"[{status_color}]{r['status']}[/{status_color}]",
            "✓" if r["clicked"] else "—",
            "[red]✓[/red]" if r["submitted_credentials"] else "—",
            "[green]✓[/green]" if r["reported"] else "—",
        )
    console.print(table)

    result = {
        "action": "identify_recipients",
        "campaign_id": campaign_id,
        "total_recipients": len(recipients),
        "clicked_count": sum(1 for r in recipients if r["clicked"]),
        "submitted_count": sum(1 for r in recipients if r["submitted_credentials"]),
        "reported_count": sum(1 for r in recipients if r["reported"]),
        "recipients": recipients,
    }
    log_action("identify_recipients", result, incident_id)
    return result


def check_credential_use(username: str, submission_timestamp: str, incident_id: str) -> dict:
    console.print(Panel(
        f"[bold yellow]ACTION: Check Stolen Credential Usage[/bold yellow]\n"
        f"User: {username}\nAfter: {submission_timestamp}",
        expand=False
    ))

    es = Elasticsearch(ELASTIC_URL, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify_certs=False)

    try:
        sub_dt = datetime.fromisoformat(submission_timestamp.replace("Z", "+00:00"))
        end_dt = sub_dt + timedelta(hours=24)
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"multi_match": {
                            "query": username,
                            "fields": ["user.name", "winlog.event_data.TargetUserName", "event_data.SubjectUserName"]
                        }},
                        {"range": {"@timestamp": {"gte": sub_dt.isoformat(), "lte": end_dt.isoformat()}}}
                    ],
                    "should": [
                        {"match": {"event.action": "logged-in"}},
                        {"match": {"event.code": "4624"}},
                        {"match": {"event.code": "4648"}},
                    ]
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "size": 50
        }
        resp = es.search(index="windows-*,auth-logs-*", body=query)
        auth_events = [hit["_source"] for hit in resp["hits"]["hits"]]
    except Exception as e:
        console.print(f"[yellow]Elastic auth search failed: {e}[/yellow]")
        auth_events = []

    # Impossible travel detection
    ips_seen = []
    impossible_travel = False
    for event in auth_events:
        ip = event.get("source", {}).get("ip") or event.get("winlog", {}).get("event_data", {}).get("IpAddress", "")
        if ip and ip not in ips_seen:
            ips_seen.append(ip)
    if len(ips_seen) > 1:
        impossible_travel = True

    risk_assessment = "LOW"
    if len(auth_events) > 0:
        risk_assessment = "MEDIUM"
    if impossible_travel:
        risk_assessment = "HIGH"
    if any(e.get("event", {}).get("outcome") == "success" for e in auth_events):
        risk_assessment = "CRITICAL" if impossible_travel else "HIGH"

    result = {
        "action": "check_credential_use",
        "username": username,
        "check_window_start": submission_timestamp,
        "check_window_end": (sub_dt + timedelta(hours=24)).isoformat(),
        "auth_events_found": len(auth_events),
        "unique_source_ips": ips_seen,
        "impossible_travel_detected": impossible_travel,
        "risk_assessment": risk_assessment,
        "auth_events_sample": auth_events[:5],
    }

    risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}[risk_assessment]
    console.print(f"\n[{risk_color}]Risk Assessment: {risk_assessment}[/{risk_color}]")
    console.print(f"Auth events found: {len(auth_events)} | Unique IPs: {len(ips_seen)} | Impossible travel: {impossible_travel}")

    create_thehive_task(
        incident_id,
        f"Credential use check: {username} — {risk_assessment} RISK",
        f"Credential use check for {username} after submission at {submission_timestamp}.\n"
        f"Auth events found: {len(auth_events)}\nUnique IPs: {ips_seen}\nImpossible travel: {impossible_travel}\n"
        f"Risk: {risk_assessment}"
    )

    log_action("check_credential_use", result, incident_id)
    return result


def force_password_reset(username: str, incident_id: str) -> dict:
    console.print(Panel(
        f"[bold red]ACTION: Force Password Reset[/bold red]\n"
        f"User: {username}",
        expand=False
    ))

    result = {
        "action": "force_password_reset",
        "username": username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "task_created",
        "note": "Lab simulation — In production, this would call the AD/LDAP API to force password reset on next login."
    }

    create_thehive_task(
        incident_id,
        f"URGENT: Force password reset — {username}",
        f"User {username} submitted credentials to a phishing site.\n\n"
        f"Required actions:\n"
        f"1. Force password reset via Active Directory (Set-ADUser -ChangePasswordAtLogon $true)\n"
        f"2. Revoke all active OAuth tokens\n"
        f"3. Terminate active VPN sessions\n"
        f"4. Force re-authentication on all SSO apps\n"
        f"5. Notify user to expect a password reset prompt\n\n"
        f"Incident: {incident_id} | Timestamp: {result['timestamp']}"
    )

    log_action("force_password_reset", result, incident_id)
    console.print(f"[green]Password reset task created in TheHive for: {username}[/green]")
    console.print(f"[dim]Lab note: In production, execute: Set-ADUser -Identity {username.split('@')[0]} -ChangePasswordAtLogon $true[/dim]")
    return result


def main():
    parser = argparse.ArgumentParser(description="Phishing Incident Containment Scripts")
    parser.add_argument("--action", required=True,
                        choices=["block_url", "block_domain", "identify_recipients",
                                 "check_credential_use", "force_password_reset"],
                        help="Containment action to perform")
    parser.add_argument("--url", help="URL to block (for block_url)")
    parser.add_argument("--domain", help="Domain to block (for block_domain)")
    parser.add_argument("--campaign-id", type=int, help="GoPhish campaign ID")
    parser.add_argument("--username", help="Username for credential check or password reset")
    parser.add_argument("--timestamp", help="Credential submission timestamp (ISO format)")
    parser.add_argument("--incident-id", required=True, help="Incident ID for audit trail")
    parser.add_argument("--reason", default="Phishing campaign containment", help="Reason for action")
    args = parser.parse_args()

    console.print(f"[bold cyan]Containment Script — Incident: {args.incident_id}[/bold cyan]\n")

    if args.action == "block_url":
        if not args.url:
            console.print("[red]--url required for block_url action[/red]")
            return
        block_url_in_proxy(args.url, args.reason, args.incident_id)

    elif args.action == "block_domain":
        if not args.domain:
            console.print("[red]--domain required for block_domain action[/red]")
            return
        block_sender_domain(args.domain, args.reason, args.incident_id)

    elif args.action == "identify_recipients":
        if not args.campaign_id:
            console.print("[red]--campaign-id required for identify_recipients action[/red]")
            return
        identify_all_recipients(args.campaign_id, args.incident_id)

    elif args.action == "check_credential_use":
        if not args.username or not args.timestamp:
            console.print("[red]--username and --timestamp required for check_credential_use[/red]")
            return
        check_credential_use(args.username, args.timestamp, args.incident_id)

    elif args.action == "force_password_reset":
        if not args.username:
            console.print("[red]--username required for force_password_reset[/red]")
            return
        force_password_reset(args.username, args.incident_id)


if __name__ == "__main__":
    main()
