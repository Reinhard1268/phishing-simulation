# Enterprise Phishing Simulation & Automated Defense
# Email parser and phishing probability scorer

import argparse
import email
import email.policy
import hashlib
import imaplib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import whois
from colorama import Fore, Style, init
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()
init(autoreset=True)
console = Console()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OUTPUT_DIR = Path("detection/email-parser/results")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

URGENCY_KEYWORDS = [
    "urgent", "immediate", "action required", "verify your", "account suspended",
    "password expir", "update now", "confirm your", "security alert", "unusual activity",
    "mfa required", "login attempt", "click here", "limited time", "24 hours",
    "access revoked", "unusual sign-in", "verify identity", "reset password"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "is.gd",
    "buff.ly", "short.link", "rebrand.ly", "cutt.ly", "tiny.cc"
]

SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work",
                   ".click", ".link", ".online", ".site", ".icu", ".buzz"]


def extract_urls(text: str) -> list[str]:
    url_pattern = re.compile(
        r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE
    )
    return list(set(url_pattern.findall(text)))


def hash_attachment(content: bytes) -> dict:
    return {
        "md5": hashlib.md5(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def check_domain_age(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            return {"domain": domain, "creation_date": str(creation), "age_days": age_days, "status": "ok"}
    except Exception as e:
        pass
    return {"domain": domain, "creation_date": None, "age_days": None, "status": "lookup_failed"}


def follow_redirect_chain(url: str, max_hops: int = 5) -> list[str]:
    chain = []
    current = url
    headers = {"User-Agent": "Mozilla/5.0 (phishing-analysis)"}
    for _ in range(max_hops):
        try:
            resp = requests.get(current, allow_redirects=False, timeout=5, headers=headers)
            chain.append({"url": current, "status_code": resp.status_code})
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                current = resp.headers["Location"]
            else:
                break
        except Exception as e:
            chain.append({"url": current, "error": str(e)})
            break
    return chain


def virustotal_url_lookup(url: str) -> dict:
    if not VT_API_KEY:
        return {"status": "skipped", "reason": "no_api_key"}
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "checked",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }
        return {"status": "not_found", "http_status": resp.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def calculate_phishing_score(headers: dict, body_text: str, urls: list[str],
                               domain_age_results: list[dict], sender_info: dict) -> dict:
    score = 0
    reasons = []

    # Urgency keywords
    body_lower = body_text.lower()
    found_keywords = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    if found_keywords:
        score += min(len(found_keywords) * 5, 30)
        reasons.append(f"Urgency keywords found: {found_keywords[:5]}")

    # External links to IP addresses
    ip_links = [u for u in urls if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u)]
    if ip_links:
        score += 25
        reasons.append(f"Links to raw IP addresses: {ip_links}")

    # Mismatched sender domain
    from_addr = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    if reply_to and reply_to:
        from_domain = re.search(r'@([\w\.-]+)', from_addr)
        reply_domain = re.search(r'@([\w\.-]+)', reply_to)
        if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
            score += 20
            reasons.append(f"Reply-To domain mismatch: From={from_domain.group(1)} ReplyTo={reply_domain.group(1)}")

    # New/young domain
    for da in domain_age_results:
        if da.get("age_days") is not None and da["age_days"] < 30:
            score += 20
            reasons.append(f"Very new domain (age {da['age_days']} days): {da['domain']}")
        elif da.get("age_days") is not None and da["age_days"] < 90:
            score += 10
            reasons.append(f"Recent domain (age {da['age_days']} days): {da['domain']}")

    # URL shorteners
    for url in urls:
        parsed = urlparse(url)
        if any(parsed.netloc.endswith(s) for s in URL_SHORTENERS):
            score += 15
            reasons.append(f"URL shortener detected: {url}")
            break

    # Suspicious TLDs
    for url in urls:
        parsed = urlparse(url)
        if any(parsed.netloc.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 10
            reasons.append(f"Suspicious TLD in URL: {url}")
            break

    # SPF/DKIM/DMARC failures (from headers if available)
    auth_results = headers.get("Authentication-Results", "")
    if "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
        score += 15
        reasons.append("SPF authentication failure")
    if "dkim=fail" in auth_results.lower() or "dkim=none" in auth_results.lower():
        score += 10
        reasons.append("DKIM authentication failure")

    # Legitimate domain indicators (reduce score)
    legitimate_domains = ["google.com", "microsoft.com", "amazon.com", "apple.com"]
    for url in urls:
        parsed = urlparse(url)
        if any(parsed.netloc.endswith(ld) for ld in legitimate_domains):
            score = max(0, score - 10)

    score = min(100, score)

    if score >= 70:
        verdict = "HIGH RISK — Likely Phishing"
        color = "red"
    elif score >= 40:
        verdict = "MEDIUM RISK — Suspicious"
        color = "yellow"
    else:
        verdict = "LOW RISK — Appears Legitimate"
        color = "green"

    return {"score": score, "verdict": verdict, "color": color, "reasons": reasons}


def parse_email_file(filepath: str) -> dict:
    with open(filepath, "rb") as f:
        raw = f.read()
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    headers = dict(msg.items())
    body_text = ""
    body_html = ""
    attachments = []

    for part in msg.walk():
        content_type = part.get_content_type()
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" in disposition.lower():
            filename = part.get_filename() or "unnamed"
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(payload),
                "hashes": hash_attachment(payload),
            })
        elif content_type == "text/plain":
            try:
                body_text += part.get_content()
            except Exception:
                body_text += part.get_payload(decode=True).decode("utf-8", errors="ignore")
        elif content_type == "text/html":
            try:
                body_html += part.get_content()
            except Exception:
                body_html += part.get_payload(decode=True).decode("utf-8", errors="ignore")

    all_text = body_text + body_html
    urls = extract_urls(all_text)

    # Analyze URLs
    url_analysis = []
    domain_ages = []
    for url in urls[:10]:  # Limit to 10 URLs to avoid rate limiting
        parsed = urlparse(url)
        domain = parsed.netloc
        da = check_domain_age(domain) if domain else {"domain": domain, "age_days": None}
        domain_ages.append(da)
        redirects = follow_redirect_chain(url)
        vt = virustotal_url_lookup(url)
        url_analysis.append({
            "url": url,
            "domain": domain,
            "domain_age": da,
            "redirect_chain": redirects,
            "virustotal": vt,
        })

    phishing_score = calculate_phishing_score(headers, all_text, urls, domain_ages, {})

    result = {
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "source_file": filepath,
        "headers": {
            "from": headers.get("From", ""),
            "to": headers.get("To", ""),
            "subject": headers.get("Subject", ""),
            "date": headers.get("Date", ""),
            "reply_to": headers.get("Reply-To", ""),
            "return_path": headers.get("Return-Path", ""),
            "x_originating_ip": headers.get("X-Originating-IP", ""),
            "authentication_results": headers.get("Authentication-Results", ""),
            "message_id": headers.get("Message-ID", ""),
        },
        "body": {
            "text_length": len(body_text),
            "html_length": len(body_html),
            "has_html": bool(body_html),
        },
        "attachments": attachments,
        "urls": url_analysis,
        "url_count": len(urls),
        "phishing_score": phishing_score,
    }
    return result


def print_report(result: dict) -> None:
    score_data = result["phishing_score"]
    color_map = {"red": "bold red", "yellow": "bold yellow", "green": "bold green"}
    rich_color = color_map.get(score_data["color"], "white")

    console.print(Panel(
        f"[bold]Phishing Probability Score: [{rich_color}]{score_data['score']}/100[/{rich_color}][/bold]\n"
        f"[{rich_color}]Verdict: {score_data['verdict']}[/{rich_color}]",
        title="[bold cyan]Email Phishing Analysis Report[/bold cyan]",
        expand=False
    ))

    h = result["headers"]
    table = Table(title="Email Headers", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", width=60)
    table.add_row("From", h["from"])
    table.add_row("To", h["to"])
    table.add_row("Subject", h["subject"])
    table.add_row("Date", h["date"])
    table.add_row("Reply-To", h["reply_to"] or "—")
    table.add_row("Return-Path", h["return_path"] or "—")
    table.add_row("X-Originating-IP", h["x_originating_ip"] or "—")
    table.add_row("Auth Results", (h["authentication_results"] or "—")[:80])
    console.print(table)

    if score_data["reasons"]:
        console.print("\n[bold yellow]Risk Factors Detected:[/bold yellow]")
        for i, reason in enumerate(score_data["reasons"], 1):
            console.print(f"  [yellow]{i}.[/yellow] {reason}")

    if result["urls"]:
        url_table = Table(title="URL Analysis", show_header=True, header_style="bold blue")
        url_table.add_column("URL", width=40)
        url_table.add_column("Domain Age", width=14)
        url_table.add_column("VT Malicious", width=14)
        url_table.add_column("Redirects", width=10)
        for ua in result["urls"]:
            age = str(ua["domain_age"].get("age_days", "?")) + " days" if ua["domain_age"].get("age_days") else "unknown"
            vt_mal = str(ua["virustotal"].get("malicious", "?"))
            redirects = str(len(ua["redirect_chain"]))
            url_table.add_row(ua["url"][:40], age, vt_mal, redirects)
        console.print(url_table)

    if result["attachments"]:
        console.print("\n[bold red]Attachments Detected:[/bold red]")
        for att in result["attachments"]:
            console.print(f"  • {att['filename']} ({att['size_bytes']} bytes) — MD5: {att['hashes']['md5']}")


def main():
    parser = argparse.ArgumentParser(description="Phishing Email Parser and Scorer")
    parser.add_argument("--input", required=True, help="Path to raw email file (.eml) or 'imap'")
    parser.add_argument("--output", default=None, help="Output JSON file path")
    args = parser.parse_args()

    console.print("[bold cyan]Project 08 — Email Parser & Phishing Scorer[/bold cyan]")
    console.print(f"[dim]Analyzing: {args.input}[/dim]\n")

    if not os.path.exists(args.input):
        console.print(f"[bold red]Error: File not found: {args.input}[/bold red]")
        sys.exit(1)

    result = parse_email_file(args.input)
    print_report(result)

    output_path = args.output or OUTPUT_DIR / f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    console.print(f"\n[bold green]Report saved to: {output_path}[/bold green]")


if __name__ == "__main__":
    main()
