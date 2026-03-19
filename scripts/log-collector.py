#  Enterprise Phishing Simulation & Automated Defense
# Collects and correlates logs from GoPhish, Elastic, and Wazuh into a unified timeline

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
ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
WAZUH_URL = os.getenv("WAZUH_URL", "http://localhost:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")


def collect_gophish_results(campaign_id: int) -> dict:
    console.print(f"[cyan]Collecting GoPhish campaign {campaign_id} results...[/cyan]")
    try:
        resp = requests.get(
            f"{GOPHISH_URL}/api/campaigns/{campaign_id}/results",
            headers={"Authorization": f"Bearer {GOPHISH_API_KEY}"},
            timeout=10, verify=False
        )
        resp.raise_for_status()
        data = resp.json()
        console.print(f"[green]  ✓ GoPhish: {len(data.get('results', []))} user records retrieved[/green]")
        return data
    except Exception as e:
        console.print(f"[yellow]  ✗ GoPhish collection failed: {e}[/yellow]")
        return {"results": [], "stats": {}}


def collect_elastic_proxy_logs(es: Elasticsearch, campaign_date: str) -> list:
    console.print(f"[cyan]Collecting Elastic proxy logs for campaign date {campaign_date}...[/cyan]")
    try:
        start = f"{campaign_date}T00:00:00Z"
        end = f"{campaign_date}T23:59:59Z"
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": start, "lte": end}}},
                        {"bool": {
                            "should": [
                                {"match": {"url.domain": "phishing-lab.local"}},
                                {"match": {"http.request.method": "POST"}},
                            ]
                        }}
                    ]
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "size": 500,
        }
        resp = es.search(index="proxy-logs-*", body=query)
        hits = [h["_source"] for h in resp["hits"]["hits"]]
        console.print(f"[green]  ✓ Elastic proxy: {len(hits)} events retrieved[/green]")
        return hits
    except Exception as e:
        console.print(f"[yellow]  ✗ Elastic proxy collection failed: {e}[/yellow]")
        return []


def collect_elastic_email_logs(es: Elasticsearch, campaign_date: str) -> list:
    console.print(f"[cyan]Collecting Elastic email gateway logs...[/cyan]")
    try:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"{campaign_date}T00:00:00Z",
                                                   "lte": f"{campaign_date}T23:59:59Z"}}},
                        {"match": {"event.category": "email"}},
                    ]
                }
            },
            "sort": [{"@timestamp": "asc"}],
            "size": 500,
        }
        resp = es.search(index="email-gateway-*", body=query)
        hits = [h["_source"] for h in resp["hits"]["hits"]]
        console.print(f"[green]  ✓ Elastic email: {len(hits)} events retrieved[/green]")
        return hits
    except Exception as e:
        console.print(f"[yellow]  ✗ Elastic email collection failed: {e}[/yellow]")
        return []


def collect_wazuh_alerts(campaign_date: str) -> list:
    console.print(f"[cyan]Collecting Wazuh phishing alerts for {campaign_date}...[/cyan]")
    try:
        auth_resp = requests.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASSWORD), verify=False, timeout=10
        )
        token = auth_resp.json().get("data", {}).get("token", "")
        headers = {"Authorization": f"Bearer {token}"}
        alert_resp = requests.get(
            f"{WAZUH_URL}/alerts?q=rule.groups:phishing&limit=500",
            headers=headers, verify=False, timeout=15
        )
        alerts = alert_resp.json().get("data", {}).get("affected_items", [])
        # Filter to campaign date
        day_alerts = [a for a in alerts if campaign_date in a.get("timestamp", "")]
        console.print(f"[green]  ✓ Wazuh: {len(day_alerts)} phishing alerts retrieved[/green]")
        return day_alerts
    except Exception as e:
        console.print(f"[yellow]  ✗ Wazuh collection failed: {e}[/yellow]")
        return []


def correlate_by_user(gophish_data: dict, proxy_logs: list,
                       email_logs: list, wazuh_alerts: list) -> dict:
    console.print("[cyan]Correlating events by user...[/cyan]")
    users = {}

    for result in gophish_data.get("results", []):
        email = result.get("email", "unknown")
        users[email] = {
            "email": email,
            "first_name": result.get("first_name"),
            "last_name": result.get("last_name"),
            "position": result.get("position"),
            "gophish": {
                "status": result.get("status"),
                "send_date": result.get("send_date"),
                "open_date": result.get("open_date"),
                "click_date": result.get("click_date"),
                "submit_date": result.get("submit_date"),
                "reported": result.get("reported", False),
                "ip": result.get("ip"),
            },
            "proxy_events": [],
            "email_events": [],
            "wazuh_alerts": [],
            "timeline": [],
        }

    # Match proxy logs to users by IP or email
    for log in proxy_logs:
        user_name = log.get("user", {}).get("name") or log.get("user.name", "")
        source_ip = log.get("source", {}).get("ip") or log.get("source.ip", "")
        for email, user in users.items():
            if (user_name and user_name in email) or \
               (source_ip and source_ip == user["gophish"].get("ip")):
                user["proxy_events"].append(log)
                break

    for log in email_logs:
        recipient = log.get("email", {}).get("to") or log.get("email.to", "")
        if recipient in users:
            users[recipient]["email_events"].append(log)

    for alert in wazuh_alerts:
        for email, user in users.items():
            agent_name = alert.get("agent", {}).get("name", "")
            if email in agent_name or agent_name in email:
                user["wazuh_alerts"].append(alert)
                break

    # Build per-user timeline
    for email, user in users.items():
        timeline = []
        gp = user["gophish"]
        if gp.get("send_date"):
            timeline.append({"ts": gp["send_date"], "event": "email_sent", "source": "gophish"})
        if gp.get("open_date"):
            timeline.append({"ts": gp["open_date"], "event": "email_opened", "source": "gophish"})
        if gp.get("click_date"):
            timeline.append({"ts": gp["click_date"], "event": "link_clicked", "source": "gophish"})
        if gp.get("submit_date"):
            timeline.append({"ts": gp["submit_date"], "event": "creds_submitted", "source": "gophish"})
        for pe in user["proxy_events"]:
            ts = pe.get("@timestamp") or pe.get("timestamp", "")
            timeline.append({"ts": ts, "event": "proxy_request", "source": "elastic",
                              "url": pe.get("url.full", pe.get("url", {}).get("full", ""))})
        for al in user["wazuh_alerts"]:
            ts = al.get("timestamp", "")
            timeline.append({"ts": ts, "event": "wazuh_alert",
                              "source": "wazuh",
                              "rule": al.get("rule", {}).get("id"),
                              "description": al.get("rule", {}).get("description", "")})
        timeline.sort(key=lambda x: x.get("ts") or "")
        user["timeline"] = timeline

    return users


def compute_statistics(gophish_data: dict, users: dict) -> dict:
    stats = gophish_data.get("stats", {})
    total = stats.get("total", len(users))
    sent = stats.get("sent", 0)
    opened = stats.get("opened", 0)
    clicked = stats.get("clicked", 0)
    submitted = stats.get("submitted_data", 0)
    reported = stats.get("email_reported", 0)
    return {
        "total_targets": total,
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "submitted": submitted,
        "reported": reported,
        "open_rate": round(opened / total * 100, 1) if total else 0,
        "click_rate": round(clicked / total * 100, 1) if total else 0,
        "submission_rate": round(submitted / total * 100, 1) if total else 0,
        "report_rate": round(reported / total * 100, 1) if total else 0,
        "users_with_proxy_events": sum(1 for u in users.values() if u["proxy_events"]),
        "users_with_wazuh_alerts": sum(1 for u in users.values() if u["wazuh_alerts"]),
        "total_proxy_events": sum(len(u["proxy_events"]) for u in users.values()),
        "total_wazuh_alerts": sum(len(u["wazuh_alerts"]) for u in users.values()),
    }


def print_summary(stats: dict, users: dict) -> None:
    table = Table(title="Campaign Log Collection Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan", width=30)
    table.add_column("Value", justify="right", width=12)

    table.add_row("Total Targets", str(stats["total_targets"]))
    table.add_row("Emails Sent", str(stats["sent"]))
    table.add_row("Emails Opened", f"{stats['opened']} ({stats['open_rate']}%)")
    table.add_row("Links Clicked", f"{stats['clicked']} ({stats['click_rate']}%)")
    table.add_row("Creds Submitted", f"[red]{stats['submitted']} ({stats['submission_rate']}%)[/red]")
    table.add_row("Emails Reported", f"[green]{stats['reported']} ({stats['report_rate']}%)[/green]")
    table.add_row("", "")
    table.add_row("Proxy Events Correlated", str(stats["total_proxy_events"]))
    table.add_row("Wazuh Alerts Correlated", str(stats["total_wazuh_alerts"]))
    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Phishing Campaign Log Collector")
    parser.add_argument("--campaign-id", type=int, required=True, help="GoPhish campaign ID")
    parser.add_argument("--output-dir", default="gophish/results", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(Panel(
        f"[bold cyan]Campaign Log Collector[/bold cyan]\nCampaign ID: {args.campaign_id}",
        expand=False
    ))

    es = Elasticsearch(ELASTIC_URL, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD), verify_certs=False)

    gophish_data = collect_gophish_results(args.campaign_id)
    campaign_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if gophish_data.get("launch_date"):
        campaign_date = gophish_data["launch_date"][:10]

    proxy_logs = collect_elastic_proxy_logs(es, campaign_date)
    email_logs = collect_elastic_email_logs(es, campaign_date)
    wazuh_alerts = collect_wazuh_alerts(campaign_date)

    users = correlate_by_user(gophish_data, proxy_logs, email_logs, wazuh_alerts)
    stats = compute_statistics(gophish_data, users)
    print_summary(stats, users)

    # Save raw results
    raw_path = output_dir / f"raw-results-{args.campaign_id}.json"
    with open(raw_path, "w") as f:
        json.dump(gophish_data, f, indent=2, default=str)

    # Save unified timeline
    timeline_path = output_dir / f"timeline-{args.campaign_id}.json"
    with open(timeline_path, "w") as f:
        json.dump({u: d["timeline"] for u, d in users.items()}, f, indent=2, default=str)

    # Save user activity
    activity_path = output_dir / f"user-activity-{args.campaign_id}.json"
    with open(activity_path, "w") as f:
        json.dump(users, f, indent=2, default=str)

    console.print(f"\n[bold green]Files saved:[/bold green]")
    console.print(f"  {raw_path}")
    console.print(f"  {timeline_path}")
    console.print(f"  {activity_path}")


if __name__ == "__main__":
    main()
