# Enterprise Phishing Simulation & Automated Defense
# Evidence collector: pulls and packages all forensic artifacts for a phishing incident

import argparse
import json
import os
import sys
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
ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://localhost:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "")


def gophish_headers() -> dict:
    return {"Authorization": f"Bearer {GOPHISH_API_KEY}"}


def get_gophish_campaign_result(campaign_id: int, user_email: str) -> dict:
    console.print(f"[cyan]Fetching GoPhish results for campaign {campaign_id}, user {user_email}...[/cyan]")
    try:
        resp = requests.get(
            f"{GOPHISH_URL}/api/campaigns/{campaign_id}/results",
            headers=gophish_headers(), timeout=10, verify=False
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        for r in results:
            if r.get("email", "").lower() == user_email.lower():
                return r
        return {"error": f"User {user_email} not found in campaign {campaign_id}"}
    except Exception as e:
        return {"error": str(e)}


def get_elastic_proxy_logs(es: Elasticsearch, user_email: str, click_time: str, window_minutes: int = 60) -> list:
    console.print(f"[cyan]Querying Elastic proxy logs for {user_email} ±{window_minutes}m of {click_time}...[/cyan]")
    try:
        click_dt = datetime.fromisoformat(click_time.replace("Z", "+00:00"))
        start = (click_dt - timedelta(minutes=window_minutes)).isoformat()
        end = (click_dt + timedelta(minutes=window_minutes)).isoformat()
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"user.name": user_email}},
                        {"range": {"@timestamp": {"gte": start, "lte": end}}}
                    ]
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "size": 200
        }
        resp = es.search(index="proxy-logs-*", body=query)
        return [hit["_source"] for hit in resp["hits"]["hits"]]
    except Exception as e:
        console.print(f"[yellow]Elastic proxy query failed: {e}[/yellow]")
        return []


def get_elastic_auth_logs(es: Elasticsearch, user_email: str, after_time: str) -> list:
    console.print(f"[cyan]Querying Elastic auth logs for {user_email} after {after_time}...[/cyan]")
    try:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"user.name": user_email}},
                        {"range": {"@timestamp": {"gte": after_time}}}
                    ]
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "size": 100
        }
        resp = es.search(index="auth-logs-*,windows-*", body=query)
        return [hit["_source"] for hit in resp["hits"]["hits"]]
    except Exception as e:
        console.print(f"[yellow]Elastic auth query failed: {e}[/yellow]")
        return []


def get_wazuh_alerts(user_email: str, campaign_id: int) -> list:
    console.print(f"[cyan]Querying Wazuh alerts related to campaign {campaign_id}...[/cyan]")
    wazuh_url = os.getenv("WAZUH_URL", "http://localhost:55000")
    wazuh_user = os.getenv("WAZUH_USER", "wazuh-wui")
    wazuh_password = os.getenv("WAZUH_PASSWORD", "")
    try:
        auth_resp = requests.post(
            f"{wazuh_url}/security/user/authenticate",
            auth=(wazuh_user, wazuh_password), verify=False, timeout=10
        )
        token = auth_resp.json().get("data", {}).get("token", "")
        headers = {"Authorization": f"Bearer {token}"}
        alert_resp = requests.get(
            f"{wazuh_url}/alerts?q=rule.groups:phishing AND agent.name:{user_email}",
            headers=headers, verify=False, timeout=10
        )
        return alert_resp.json().get("data", {}).get("affected_items", [])
    except Exception as e:
        console.print(f"[yellow]Wazuh query failed: {e}[/yellow]")
        return []


def build_timeline(gophish_result: dict, proxy_logs: list, auth_logs: list, wazuh_alerts: list) -> list:
    timeline = []

    if gophish_result.get("send_date"):
        timeline.append({
            "timestamp": gophish_result["send_date"],
            "event_type": "email_sent",
            "source": "gophish",
            "description": f"Phishing email sent to {gophish_result.get('email', 'unknown')}",
            "details": {}
        })
    if gophish_result.get("open_date"):
        timeline.append({
            "timestamp": gophish_result["open_date"],
            "event_type": "email_opened",
            "source": "gophish",
            "description": "Phishing email opened (tracking pixel fired)",
            "details": {"ip": gophish_result.get("ip", "")}
        })
    if gophish_result.get("click_date"):
        timeline.append({
            "timestamp": gophish_result["click_date"],
            "event_type": "link_clicked",
            "source": "gophish",
            "description": "Phishing link clicked",
            "details": {"ip": gophish_result.get("ip", ""), "user_agent": gophish_result.get("details", {}).get("user_agent", "")}
        })
    if gophish_result.get("submit_date"):
        timeline.append({
            "timestamp": gophish_result["submit_date"],
            "event_type": "credentials_submitted",
            "source": "gophish",
            "description": "Credentials submitted to phishing landing page",
            "details": {"username_captured": gophish_result.get("details", {}).get("username", ""),
                        "ip": gophish_result.get("ip", "")}
        })

    for log in proxy_logs:
        ts = log.get("@timestamp", log.get("timestamp", ""))
        timeline.append({
            "timestamp": ts,
            "event_type": "proxy_request",
            "source": "elastic_proxy",
            "description": f"Proxy: {log.get('http.request.method', 'GET')} {log.get('url.full', log.get('proxy.url', ''))}",
            "details": {"status_code": log.get("http.response.status_code", ""), "bytes": log.get("http.response.body.bytes", "")}
        })

    for auth in auth_logs:
        ts = auth.get("@timestamp", auth.get("timestamp", ""))
        timeline.append({
            "timestamp": ts,
            "event_type": "authentication_event",
            "source": "elastic_auth",
            "description": f"Auth event: {auth.get('event.action', 'login')} — {auth.get('event.outcome', 'unknown')}",
            "details": {"source_ip": auth.get("source.ip", ""), "target": auth.get("winlog.event_data.WorkstationName", "")}
        })

    for alert in wazuh_alerts:
        timeline.append({
            "timestamp": alert.get("timestamp", ""),
            "event_type": "siem_alert",
            "source": "wazuh",
            "description": f"SIEM Alert: {alert.get('rule', {}).get('description', '')}",
            "details": {"rule_id": alert.get("rule", {}).get("id", ""), "level": alert.get("rule", {}).get("level", "")}
        })

    timeline.sort(key=lambda x: x.get("timestamp", "") or "")
    return timeline


def upload_to_thehive(incident_id: str, evidence_bundle: dict, summary_md: str) -> bool:
    console.print(f"[cyan]Uploading evidence bundle to TheHive case {incident_id}...[/cyan]")
    headers = {"Authorization": f"Bearer {THEHIVE_API_KEY}", "Content-Type": "application/json"}
    try:
        obs_payload = {
            "dataType": "other",
            "data": json.dumps(evidence_bundle)[:1048576],
            "message": f"Evidence bundle for incident {incident_id}",
            "tags": ["phishing", "evidence", "automated"],
            "ioc": False
        }
        case_resp = requests.get(
            f"{THEHIVE_URL}/api/case?q=title:{incident_id}",
            headers=headers, timeout=10
        )
        cases = case_resp.json()
        if isinstance(cases, list) and len(cases) > 0:
            case_id = cases[0]["id"]
            requests.post(
                f"{THEHIVE_URL}/api/case/{case_id}/artifact",
                headers=headers, json=obs_payload, timeout=15
            )
            console.print(f"[green]Evidence uploaded to TheHive case {case_id}[/green]")
            return True
        console.print(f"[yellow]TheHive case for {incident_id} not found — skipping upload[/yellow]")
        return False
    except Exception as e:
        console.print(f"[yellow]TheHive upload failed: {e}[/yellow]")
        return False


def generate_summary_md(incident_id: str, user_email: str, gophish_result: dict,
                         timeline: list, proxy_logs: list, auth_logs: list) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# Evidence Summary — {incident_id}",
        f"**Generated:** {now}",
        f"**Subject User:** {user_email}",
        "",
        "## GoPhish Campaign Result",
        f"- Status: {gophish_result.get('status', 'unknown')}",
        f"- Email Sent: {gophish_result.get('send_date', 'N/A')}",
        f"- Email Opened: {gophish_result.get('open_date', 'N/A')}",
        f"- Link Clicked: {gophish_result.get('click_date', 'N/A')}",
        f"- Credentials Submitted: {gophish_result.get('submit_date', 'N/A')}",
        f"- Source IP at Click: {gophish_result.get('ip', 'N/A')}",
        "",
        f"## Event Timeline ({len(timeline)} events)",
        "",
        "| Timestamp | Event Type | Source | Description |",
        "|-----------|-----------|--------|-------------|",
    ]
    for event in timeline:
        ts = (event.get("timestamp") or "")[:19].replace("T", " ")
        lines.append(f"| {ts} | {event['event_type']} | {event['source']} | {event['description'][:60]} |")

    lines += [
        "",
        f"## Supporting Log Counts",
        f"- Proxy log events: {len(proxy_logs)}",
        f"- Auth log events: {len(auth_logs)}",
        "",
        "## Investigator Notes",
        "_[Add analyst notes here before closing the incident]_",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Phishing Evidence Collector")
    parser.add_argument("--campaign-id", type=int, required=True, help="GoPhish campaign ID")
    parser.add_argument("--user-email", required=True, help="Target user email to collect evidence for")
    parser.add_argument("--incident-id", required=True, help="Incident ID (e.g. INC-2024-001)")
    parser.add_argument("--output-dir", default="ir-workflow/evidence-collection/bundles")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(Panel(
        f"[bold cyan]Phishing Evidence Collector[/bold cyan]\n"
        f"Incident: [bold]{args.incident_id}[/bold] | User: [bold]{args.user_email}[/bold]",
        expand=False
    ))

    es = Elasticsearch(
        ELASTIC_URL,
        basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        verify_certs=False
    )

    gophish_result = get_gophish_campaign_result(args.campaign_id, args.user_email)
    click_time = gophish_result.get("click_date") or datetime.now(timezone.utc).isoformat()

    proxy_logs = get_elastic_proxy_logs(es, args.user_email, click_time)
    auth_logs = get_elastic_auth_logs(es, args.user_email, click_time)
    wazuh_alerts = get_wazuh_alerts(args.user_email, args.campaign_id)

    timeline = build_timeline(gophish_result, proxy_logs, auth_logs, wazuh_alerts)

    evidence_bundle = {
        "incident_id": args.incident_id,
        "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        "subject_user": args.user_email,
        "campaign_id": args.campaign_id,
        "gophish_result": gophish_result,
        "proxy_logs": proxy_logs,
        "auth_logs": auth_logs,
        "wazuh_alerts": wazuh_alerts,
        "unified_timeline": timeline,
    }

    bundle_path = output_dir / f"evidence-{args.incident_id.replace('/', '-')}.json"
    with open(bundle_path, "w") as f:
        json.dump(evidence_bundle, f, indent=2, default=str)

    summary_md = generate_summary_md(
        args.incident_id, args.user_email, gophish_result, timeline, proxy_logs, auth_logs
    )
    summary_path = output_dir / f"evidence-summary-{args.incident_id.replace('/', '-')}.md"
    with open(summary_path, "w") as f:
        f.write(summary_md)

    upload_to_thehive(args.incident_id, evidence_bundle, summary_md)

    table = Table(title=f"Evidence Collection Summary — {args.incident_id}")
    table.add_column("Item", style="cyan")
    table.add_column("Count / Status", style="green")
    table.add_row("GoPhish result", gophish_result.get("status", "collected"))
    table.add_row("Proxy log events", str(len(proxy_logs)))
    table.add_row("Auth log events", str(len(auth_logs)))
    table.add_row("Wazuh alerts", str(len(wazuh_alerts)))
    table.add_row("Timeline events", str(len(timeline)))
    table.add_row("Bundle saved", str(bundle_path))
    table.add_row("Summary saved", str(summary_path))
    console.print(table)


if __name__ == "__main__":
    main()
