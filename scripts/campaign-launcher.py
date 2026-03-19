# Enterprise Phishing Simulation & Automated Defense
# GoPhish campaign launcher with pre-flight checks, live monitoring, and Slack notification

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from colorama import Fore, Style, init
from dotenv import load_dotenv
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

load_dotenv()
init(autoreset=True)
console = Console()

GOPHISH_URL = os.getenv("GOPHISH_URL", "http://localhost:3333")
GOPHISH_API_KEY = os.getenv("GOPHISH_API_KEY", "")
MAILHOG_URL = os.getenv("MAILHOG_URL", "http://localhost:8025")
PHISHING_LAB_DOMAIN = os.getenv("PHISHING_LAB_DOMAIN", "phishing-lab.local")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
RESULTS_DIR = Path("gophish/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

GOPHISH_HEADERS = {
    "Authorization": f"Bearer {GOPHISH_API_KEY}",
    "Content-Type": "application/json",
}


def gophish_get(endpoint: str) -> dict:
    resp = requests.get(
        f"{GOPHISH_URL}/api/{endpoint}",
        headers=GOPHISH_HEADERS, timeout=10, verify=False
    )
    resp.raise_for_status()
    return resp.json()


def gophish_post(endpoint: str, payload: dict) -> dict:
    resp = requests.post(
        f"{GOPHISH_URL}/api/{endpoint}",
        headers=GOPHISH_HEADERS, json=payload, timeout=15, verify=False
    )
    resp.raise_for_status()
    return resp.json()


def check_smtp_profile(profile_name: str) -> bool:
    console.print(f"  Checking SMTP profile: [cyan]{profile_name}[/cyan]", end=" ")
    try:
        profiles = gophish_get("smtp")
        for profile in profiles:
            if profile.get("name") == profile_name:
                resp = requests.get(MAILHOG_URL, timeout=5)
                if resp.status_code == 200:
                    console.print("[green]✓ SMTP accessible (MailHog up)[/green]")
                    return True
        console.print(f"[red]✗ Profile '{profile_name}' not found in GoPhish[/red]")
        return False
    except Exception as e:
        console.print(f"[red]✗ SMTP check failed: {e}[/red]")
        return False


def check_landing_page(page_name: str) -> bool:
    console.print(f"  Checking landing page: [cyan]{page_name}[/cyan]", end=" ")
    try:
        pages = gophish_get("pages")
        for page in pages:
            if page.get("name") == page_name:
                console.print("[green]✓ Landing page found in GoPhish[/green]")
                return True
        console.print(f"[red]✗ Landing page '{page_name}' not found[/red]")
        return False
    except Exception as e:
        console.print(f"[red]✗ Landing page check failed: {e}[/red]")
        return False


def check_target_group(group_name: str) -> tuple[bool, int]:
    console.print(f"  Checking target group: [cyan]{group_name}[/cyan]", end=" ")
    try:
        groups = gophish_get("groups")
        for group in groups:
            if group.get("name") == group_name:
                count = len(group.get("targets", []))
                console.print(f"[green]✓ Group found — {count} targets[/green]")
                return True, count
        console.print(f"[red]✗ Target group '{group_name}' not found[/red]")
        return False, 0
    except Exception as e:
        console.print(f"[red]✗ Target group check failed: {e}[/red]")
        return False, 0


def run_preflight_checks(config: dict) -> tuple[bool, int]:
    console.print(Panel("[bold cyan]Pre-Launch Checks[/bold cyan]", expand=False))
    smtp_name = config.get("smtp", {}).get("name", "lab-smtp")
    page_name = config.get("page", {}).get("name", "")
    group_name = (config.get("groups") or [{}])[0].get("name", "lab-users")

    smtp_ok = check_smtp_profile(smtp_name)
    page_ok = check_landing_page(page_name)
    group_ok, target_count = check_target_group(group_name)

    all_ok = smtp_ok and page_ok and group_ok
    if all_ok:
        console.print(f"\n[bold green]✅ All pre-flight checks passed. {target_count} targets ready.[/bold green]")
    else:
        console.print("\n[bold red]❌ Pre-flight checks FAILED. Resolve issues before launching.[/bold red]")
    return all_ok, target_count


def send_slack_notification(message: str) -> None:
    if not SLACK_WEBHOOK_URL:
        return
    try:
        payload = {
            "text": message,
            "username": "GoPhish-Bot",
            "icon_emoji": ":fishing_pole_and_fish:"
        }
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=8)
    except Exception:
        pass


def get_live_stats(campaign_id: int) -> dict:
    try:
        results = gophish_get(f"campaigns/{campaign_id}/results")
        stats = results.get("stats", {})
        return {
            "sent": stats.get("sent", 0),
            "opened": stats.get("opened", 0),
            "clicked": stats.get("clicked", 0),
            "submitted": stats.get("submitted_data", 0),
            "reported": stats.get("email_reported", 0),
        }
    except Exception:
        return {"sent": 0, "opened": 0, "clicked": 0, "submitted": 0, "reported": 0}


def build_stats_table(stats: dict, target_count: int, elapsed_seconds: int, campaign_name: str) -> Table:
    table = Table(
        title=f"[bold cyan]{campaign_name}[/bold cyan] — Live Stats",
        show_header=True,
        header_style="bold white on blue",
        box=None
    )
    table.add_column("Metric", style="bold", width=22)
    table.add_column("Count", justify="center", width=10)
    table.add_column("Rate", justify="center", width=12)
    table.add_column("Visual", width=30)

    def bar(count, total, color):
        if total == 0:
            return ""
        filled = int((count / total) * 20)
        return f"[{color}]{'█' * filled}[/{color}]{'░' * (20 - filled)}"

    total = target_count or 1
    elapsed_str = f"{elapsed_seconds // 60}m {elapsed_seconds % 60}s"

    table.add_row("Emails Sent",    str(stats["sent"]),      f"{stats['sent']/total*100:.1f}%",      bar(stats["sent"],      total, "blue"))
    table.add_row("Emails Opened",  str(stats["opened"]),    f"{stats['opened']/total*100:.1f}%",    bar(stats["opened"],    total, "yellow"))
    table.add_row("Links Clicked",  str(stats["clicked"]),   f"{stats['clicked']/total*100:.1f}%",   bar(stats["clicked"],   total, "red"))
    table.add_row("Creds Submitted",str(stats["submitted"]), f"{stats['submitted']/total*100:.1f}%", bar(stats["submitted"], total, "bold red"))
    table.add_row("Emails Reported",str(stats["reported"]),  f"{stats['reported']/total*100:.1f}%",  bar(stats["reported"],  total, "green"))
    table.add_row("", "", "", "")
    table.add_row("[dim]Elapsed Time[/dim]", f"[dim]{elapsed_str}[/dim]", "", "")
    return table


def resolve_target_count(config: dict) -> int:
    group_name = (config.get("groups") or [{}])[0].get("name", "lab-users")
    try:
        groups = gophish_get("groups")
        for g in groups:
            if g.get("name") == group_name:
                return len(g.get("targets", []))
    except Exception:
        pass
    return 10


def launch_campaign(config: dict, dry_run: bool, delay_minutes: int) -> None:
    campaign_name = config.get("name", "Unknown Campaign")

    if dry_run:
        console.print(Panel(
            f"[bold yellow]DRY RUN MODE[/bold yellow]\n"
            f"Campaign:     [cyan]{campaign_name}[/cyan]\n"
            f"Targets:      {(config.get('groups') or [{}])[0].get('name', 'lab-users')}\n"
            f"Template:     {config.get('template', {}).get('name', 'N/A')}\n"
            f"Landing Page: {config.get('page', {}).get('name', 'N/A')}\n"
            f"SMTP:         {config.get('smtp', {}).get('name', 'N/A')}\n"
            f"URL:          {config.get('url', 'N/A')}\n\n"
            f"[dim]No campaign launched. Remove --dry-run to go live.[/dim]",
            title="Campaign Preview",
            expand=False
        ))
        return

    if delay_minutes > 0:
        console.print(f"[yellow]Waiting {delay_minutes} minute(s) before launch...[/yellow]")
        for remaining in range(delay_minutes * 60, 0, -60):
            console.print(f"  Launch in {remaining // 60}m...")
            time.sleep(60)

    console.print(f"\n[bold cyan]Launching campaign: {campaign_name}[/bold cyan]")
    try:
        result = gophish_post("campaigns", config)
        campaign_id = result.get("id")
        if not campaign_id:
            console.print("[red]Campaign launch failed — no campaign ID returned[/red]")
            console.print(json.dumps(result, indent=2))
            return
        console.print(f"[bold green]Campaign launched! GoPhish ID: {campaign_id}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Campaign launch failed: {e}[/bold red]")
        return

    send_slack_notification(
        f":fishing_pole_and_fish: *GoPhish Campaign Launched*\n"
        f"Name: `{campaign_name}`\n"
        f"ID: `{campaign_id}`\n"
        f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    )

    target_count = resolve_target_count(config)
    console.print("\n[bold]Monitoring campaign progress — Ctrl+C to stop...[/bold]")
    start_time = time.time()
    live_results = {"sent": 0, "opened": 0, "clicked": 0, "submitted": 0, "reported": 0}

    try:
        with Live(console=console, refresh_per_second=0.5) as live:
            while True:
                stats = get_live_stats(campaign_id)
                elapsed = int(time.time() - start_time)
                live.update(build_stats_table(stats, target_count, elapsed, campaign_name))
                live_results = stats

                results_path = RESULTS_DIR / f"live-{campaign_name.lower().replace(' ', '-')}.json"
                with open(results_path, "w") as f:
                    json.dump({
                        "campaign_id": campaign_id,
                        "campaign_name": campaign_name,
                        "last_updated": datetime.now(timezone.utc).isoformat(),
                        "stats": stats,
                    }, f, indent=2)

                time.sleep(60)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")

    console.print("\n[bold green]Final Campaign Summary:[/bold green]")
    console.print(build_stats_table(live_results, target_count, int(time.time() - start_time), campaign_name))

    send_slack_notification(
        f":bar_chart: *GoPhish Campaign Complete*\n"
        f"Name: `{campaign_name}` (ID: {campaign_id})\n"
        f"Sent={live_results['sent']} | "
        f"Opened={live_results['opened']} | "
        f"Clicked={live_results['clicked']} | "
        f"Submitted={live_results['submitted']} | "
        f"Reported={live_results['reported']}"
    )

    console.print("\n[cyan]Triggering log-collector.py in background...[/cyan]")
    try:
        subprocess.Popen([
            sys.executable, "scripts/log-collector.py",
            "--campaign-id", str(campaign_id),
            "--output-dir", str(RESULTS_DIR)
        ])
        console.print("[green]log-collector.py launched.[/green]")
    except Exception as e:
        console.print(f"[yellow]Could not launch log-collector: {e}[/yellow]")


def main():
    parser = argparse.ArgumentParser(description="GoPhish Campaign Launcher")
    parser.add_argument("--config", required=True, help="Path to campaign config JSON")
    parser.add_argument("--dry-run", action="store_true", help="Preview without launching")
    parser.add_argument("--delay-minutes", type=int, default=0, help="Delay before launch (minutes)")
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]GoPhish Campaign Launcher[/bold cyan]\n"
        "Project 08 — Enterprise Phishing Simulation & Automated Defense",
        expand=False
    ))

    config_path = Path(args.config)
    if not config_path.exists():
        console.print(f"[red]Config file not found: {args.config}[/red]")
        sys.exit(1)

    with open(config_path) as f:
        config = json.load(f)

    console.print(f"Config: [cyan]{config_path}[/cyan]")
    console.print(f"Campaign: [bold]{config.get('name', 'unknown')}[/bold]\n")

    all_ok, target_count = run_preflight_checks(config)
    if not args.dry_run and not all_ok:
        console.print("[red]Aborting — pre-flight checks failed.[/red]")
        sys.exit(1)

    launch_campaign(config, args.dry_run, args.delay_minutes)


if __name__ == "__main__":
    main()
