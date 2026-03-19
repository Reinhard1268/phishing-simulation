# Enterprise Phishing Simulation & Automated Defense
# Email header analyzer: full routing trace, authentication analysis, spoofing detection

import argparse
import email
import email.policy
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

load_dotenv()
console = Console()

VT_API_KEY = __import__("os").getenv("VIRUSTOTAL_API_KEY", "")


def parse_received_headers(received_headers: list[str]) -> list[dict]:
    hops = []
    for header in received_headers:
        hop = {
            "raw": header,
            "from_host": None,
            "by_host": None,
            "ip": None,
            "timestamp": None,
            "protocol": None
        }
        from_match = re.search(r'from\s+([\w\.\-\[\]]+)', header, re.IGNORECASE)
        by_match = re.search(r'by\s+([\w\.\-]+)', header, re.IGNORECASE)
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        ts_match = re.search(r';\s*(.+)$', header)
        proto_match = re.search(r'with\s+([\w]+)', header, re.IGNORECASE)

        if from_match:
            hop["from_host"] = from_match.group(1)
        if by_match:
            hop["by_host"] = by_match.group(1)
        if ip_match:
            hop["ip"] = ip_match.group(1)
        if ts_match:
            hop["timestamp"] = ts_match.group(1).strip()
        if proto_match:
            hop["protocol"] = proto_match.group(1)
        hops.append(hop)
    return list(reversed(hops))  # First hop first


def check_spf(domain: str) -> dict:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata)
            if "v=spf1" in txt:
                return {"domain": domain, "spf_record": txt, "has_spf": True}
        return {"domain": domain, "spf_record": None, "has_spf": False}
    except Exception as e:
        return {"domain": domain, "spf_record": None, "has_spf": False, "error": str(e)}


def check_dkim(domain: str, selector: str = "default") -> dict:
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, "TXT")
        for rdata in answers:
            txt = str(rdata)
            if "v=DKIM1" in txt or "k=rsa" in txt:
                return {"domain": dkim_domain, "dkim_record": txt, "has_dkim": True}
        return {"domain": dkim_domain, "dkim_record": None, "has_dkim": False}
    except Exception as e:
        return {"domain": dkim_domain, "dkim_record": None, "has_dkim": False, "error": str(e)}


def check_dmarc(domain: str) -> dict:
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = str(rdata)
            if "v=DMARC1" in txt:
                policy_match = re.search(r'p=(\w+)', txt)
                return {
                    "domain": dmarc_domain,
                    "dmarc_record": txt,
                    "has_dmarc": True,
                    "policy": policy_match.group(1) if policy_match else "unknown"
                }
        return {"domain": dmarc_domain, "dmarc_record": None, "has_dmarc": False}
    except Exception as e:
        return {"domain": dmarc_domain, "dmarc_record": None, "has_dmarc": False, "error": str(e)}


def check_ip_reputation(ip: str) -> dict:
    if not ip:
        return {"ip": ip, "status": "no_ip"}
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            return {"ip": ip, "is_private": True, "status": "internal"}
    except ValueError:
        return {"ip": ip, "status": "invalid_ip"}

    if VT_API_KEY:
        try:
            headers = {"x-apikey": VT_API_KEY}
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers, timeout=10
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "ip": ip,
                    "is_private": False,
                    "vt_malicious": stats.get("malicious", 0),
                    "vt_suspicious": stats.get("suspicious", 0),
                    "country": data.get("country", "unknown"),
                    "as_owner": data.get("as_owner", "unknown"),
                    "status": "checked"
                }
        except Exception:
            pass

    # Fallback: basic AbuseIPDB check (no key needed for basic info)
    return {"ip": ip, "is_private": False, "status": "reputation_unavailable"}


def detect_spoofing_indicators(headers: dict) -> list[str]:
    indicators = []

    from_addr = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")
    sender = headers.get("Sender", "")

    from_domain_match = re.search(r'@([\w\.\-]+)', from_addr)
    reply_domain_match = re.search(r'@([\w\.\-]+)', reply_to) if reply_to else None
    return_domain_match = re.search(r'@([\w\.\-]+)', return_path) if return_path else None

    from_domain = from_domain_match.group(1) if from_domain_match else ""

    if reply_domain_match and from_domain and reply_domain_match.group(1) != from_domain:
        indicators.append(
            f"Reply-To domain mismatch: From=@{from_domain} but Reply-To=@{reply_domain_match.group(1)}"
        )
    if return_domain_match and from_domain and return_domain_match.group(1) != from_domain:
        indicators.append(
            f"Return-Path domain mismatch: From=@{from_domain} but Return-Path=@{return_domain_match.group(1)}"
        )

    # Display name vs actual address mismatch
    display_match = re.match(r'^(.+?)\s*<', from_addr)
    if display_match:
        display_name = display_match.group(1).strip().lower()
        known_brands = ["microsoft", "apple", "google", "amazon", "paypal", "fedex", "ups", "canada post"]
        for brand in known_brands:
            if brand in display_name and brand not in from_domain.lower():
                indicators.append(
                    f"Brand impersonation: Display name contains '{brand}' but domain is '{from_domain}'"
                )

    auth_results = headers.get("Authentication-Results", "")
    if "spf=fail" in auth_results.lower():
        indicators.append("SPF FAIL in Authentication-Results header")
    elif "spf=softfail" in auth_results.lower():
        indicators.append("SPF SOFTFAIL in Authentication-Results header")
    if "dkim=fail" in auth_results.lower():
        indicators.append("DKIM FAIL in Authentication-Results header")
    if "dmarc=fail" in auth_results.lower():
        indicators.append("DMARC FAIL in Authentication-Results header")

    if headers.get("X-Priority") in ("1", "2") or headers.get("Importance", "").lower() == "high":
        indicators.append("Email marked as high priority/importance — common in phishing")

    return indicators


def analyze_email_file(filepath: str) -> dict:
    with open(filepath, "rb") as f:
        raw = f.read()
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    headers = dict(msg.items())

    received_headers = msg.get_all("Received", [])
    hops = parse_received_headers(received_headers)

    from_addr = headers.get("From", "")
    from_domain_match = re.search(r'@([\w\.\-]+)', from_addr)
    from_domain = from_domain_match.group(1) if from_domain_match else ""

    originating_ip = None
    if hops:
        for hop in hops:
            if hop.get("ip"):
                try:
                    addr = ipaddress.ip_address(hop["ip"])
                    if not addr.is_private:
                        originating_ip = hop["ip"]
                        break
                except ValueError:
                    pass

    spf = check_spf(from_domain) if from_domain else {}
    dkim_selector = "default"
    dkim_selector_match = re.search(r's=([\w\.\-]+);', headers.get("DKIM-Signature", ""))
    if dkim_selector_match:
        dkim_selector = dkim_selector_match.group(1)
    dkim = check_dkim(from_domain, dkim_selector) if from_domain else {}
    dmarc = check_dmarc(from_domain) if from_domain else {}
    ip_rep = check_ip_reputation(originating_ip) if originating_ip else {}
    spoofing_indicators = detect_spoofing_indicators(headers)

    risk_score = 0
    if not spf.get("has_spf"):
        risk_score += 15
    if not dkim.get("has_dkim"):
        risk_score += 10
    if not dmarc.get("has_dmarc"):
        risk_score += 10
    if "spf=fail" in headers.get("Authentication-Results", "").lower():
        risk_score += 25
    if "dkim=fail" in headers.get("Authentication-Results", "").lower():
        risk_score += 20
    if ip_rep.get("vt_malicious", 0) > 0:
        risk_score += 30
    risk_score += len(spoofing_indicators) * 10
    risk_score = min(100, risk_score)

    return {
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": filepath,
        "from_address": from_addr,
        "from_domain": from_domain,
        "subject": headers.get("Subject", ""),
        "date": headers.get("Date", ""),
        "message_id": headers.get("Message-ID", ""),
        "originating_ip": originating_ip,
        "routing_hops": hops,
        "authentication": {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "auth_results_header": headers.get("Authentication-Results", ""),
        },
        "ip_reputation": ip_rep,
        "spoofing_indicators": spoofing_indicators,
        "risk_score": risk_score,
        "all_headers": headers,
    }


def print_analysis(result: dict) -> None:
    risk = result["risk_score"]
    color = "red" if risk >= 60 else ("yellow" if risk >= 30 else "green")

    console.print(Panel(
        f"[bold]Header Risk Score: [{color}]{risk}/100[/{color}][/bold]\n"
        f"From: {result['from_address']}\n"
        f"Subject: {result['subject']}",
        title="[bold cyan]Email Header Analysis[/bold cyan]",
        expand=False
    ))

    hop_table = Table(title="Email Routing Path (First → Last Hop)")
    hop_table.add_column("#", width=4)
    hop_table.add_column("From Host", style="cyan")
    hop_table.add_column("IP Address", style="yellow")
    hop_table.add_column("By Host")
    hop_table.add_column("Protocol")
    for i, hop in enumerate(result["routing_hops"], 1):
        hop_table.add_row(
            str(i),
            hop.get("from_host") or "—",
            hop.get("ip") or "—",
            hop.get("by_host") or "—",
            hop.get("protocol") or "—",
        )
    console.print(hop_table)

    auth = result["authentication"]
    auth_table = Table(title="Email Authentication Results")
    auth_table.add_column("Check", style="cyan")
    auth_table.add_column("Record Found", width=14)
    auth_table.add_column("Details")
    auth_table.add_row("SPF", "✓" if auth["spf"].get("has_spf") else "✗",
                       (auth["spf"].get("spf_record") or "No SPF record")[:60])
    auth_table.add_row("DKIM", "✓" if auth["dkim"].get("has_dkim") else "✗",
                       (auth["dkim"].get("dkim_record") or "No DKIM record")[:60])
    auth_table.add_row("DMARC", "✓" if auth["dmarc"].get("has_dmarc") else "✗",
                       f"Policy: {auth['dmarc'].get('policy', 'N/A')}")
    console.print(auth_table)

    if result["originating_ip"]:
        ip_rep = result["ip_reputation"]
        console.print(f"\n[bold]Originating IP:[/bold] {result['originating_ip']}")
        console.print(f"  Country: {ip_rep.get('country', 'unknown')}")
        console.print(f"  AS Owner: {ip_rep.get('as_owner', 'unknown')}")
        console.print(f"  VT Malicious: {ip_rep.get('vt_malicious', 'not checked')}")

    if result["spoofing_indicators"]:
        console.print("\n[bold red]⚠ Spoofing Indicators:[/bold red]")
        for ind in result["spoofing_indicators"]:
            console.print(f"  [red]•[/red] {ind}")
    else:
        console.print("\n[bold green]✓ No spoofing indicators detected[/bold green]")


def main():
    parser = argparse.ArgumentParser(description="Email Header Analyzer")
    parser.add_argument("--input", required=True, help="Path to .eml file")
    parser.add_argument("--output", default=None, help="Output JSON report path")
    args = parser.parse_args()

    if not __import__("os").path.exists(args.input):
        console.print(f"[red]File not found: {args.input}[/red]")
        sys.exit(1)

    result = analyze_email_file(args.input)
    print_analysis(result)

    output_path = args.output or f"ir-workflow/evidence-collection/header-analysis-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    console.print(f"\n[green]Analysis saved to: {output_path}[/green]")


if __name__ == "__main__":
    main()
