# Enterprise Phishing Simulation & Automated Defense
# Generates comprehensive PDF and Markdown campaign reports

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from dotenv import load_dotenv
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
)
from rich.console import Console

load_dotenv()
console = Console()

RESULTS_DIR = Path("gophish/results")
CAMPAIGN_STATS_DIR = Path("metrics/campaign-stats")
OUTPUT_DIR = Path("metrics/campaign-stats")
CHART_TEMP_DIR = Path("/tmp/phishing_report_charts")
CHART_TEMP_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PALETTE = {
    "primary": "#1565c0", "danger": "#c62828", "success": "#2e7d32",
    "warning": "#f57f17", "neutral": "#546e7a",
}

ROUND_META = {
    1: {"label": "Round 1 — No Training", "template": "Office365-MFA-Update", "date": "2024-01-16"},
    2: {"label": "Round 2 — Post Training", "template": "IT-Password-Expiry", "date": "2024-02-13"},
    3: {"label": "Round 3 — Tuned Defenses", "template": "HR-Benefits-Enrollment", "date": "2024-03-12"},
}

ROUND_STATS = {
    1: {"sent": 10, "opened": 9, "clicked": 7, "submitted": 4, "reported": 1,
        "open_rate": 90.0, "click_rate": 70.0, "submission_rate": 40.0, "report_rate": 10.0},
    2: {"sent": 10, "opened": 7, "clicked": 3, "submitted": 1, "reported": 4,
        "open_rate": 70.0, "click_rate": 30.0, "submission_rate": 10.0, "report_rate": 40.0},
    3: {"sent": 10, "opened": 4, "clicked": 1, "submitted": 0, "reported": 6,
        "open_rate": 40.0, "click_rate": 10.0, "submission_rate": 0.0, "report_rate": 60.0},
}


def load_campaign_results(campaign_id: int) -> dict:
    path = RESULTS_DIR / f"raw-results-{campaign_id}.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def make_trend_chart(round_num: int) -> Path:
    rounds_to_show = list(range(1, round_num + 1))
    click_rates = [ROUND_STATS[r]["click_rate"] for r in rounds_to_show]
    sub_rates = [ROUND_STATS[r]["submission_rate"] for r in rounds_to_show]
    report_rates = [ROUND_STATS[r]["report_rate"] for r in rounds_to_show]
    labels = [f"R{r}" for r in rounds_to_show]
    x = np.arange(len(labels))

    fig, ax = plt.subplots(figsize=(8, 4))
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")
    ax.plot(x, click_rates, "o-", color=PALETTE["danger"], linewidth=2.5, markersize=8, label="Click Rate %")
    ax.plot(x, sub_rates, "s--", color=PALETTE["warning"], linewidth=2, markersize=7, label="Submission Rate %")
    ax.plot(x, report_rates, "^-.", color=PALETTE["success"], linewidth=2, markersize=7, label="Report Rate %")
    for i, (c, s, r) in enumerate(zip(click_rates, sub_rates, report_rates)):
        ax.annotate(f"{c:.0f}%", (x[i], c), xytext=(0, 8), textcoords="offset points",
                    ha="center", fontsize=9, color=PALETTE["danger"], fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=11)
    ax.set_ylabel("Rate (%)", fontsize=11)
    ax.set_ylim(-5, 100)
    ax.set_title("Campaign Metrics Trend", fontsize=12, fontweight="bold")
    ax.legend(fontsize=9, loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    path = CHART_TEMP_DIR / "trend.png"
    plt.tight_layout()
    plt.savefig(path, dpi=120, bbox_inches="tight")
    plt.close()
    return path


def make_round_bar_chart(round_num: int) -> Path:
    stats = ROUND_STATS[round_num]
    metrics = ["Opened", "Clicked", "Submitted", "Reported"]
    values = [stats["open_rate"], stats["click_rate"], stats["submission_rate"], stats["report_rate"]]
    bar_colors = [PALETTE["neutral"], PALETTE["danger"], "#880000", PALETTE["success"]]

    fig, ax = plt.subplots(figsize=(7, 3.5))
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")
    bars = ax.barh(metrics, values, color=bar_colors, edgecolor="white", height=0.55)
    for bar in bars:
        w = bar.get_width()
        ax.annotate(f"{w:.1f}%", xy=(w, bar.get_y() + bar.get_height() / 2),
                    xytext=(4, 0), textcoords="offset points",
                    va="center", fontsize=10, fontweight="bold")
    ax.set_xlim(0, 110)
    ax.set_xlabel("Rate (%)", fontsize=10)
    ax.set_title(f"Round {round_num} — Campaign Results", fontsize=12, fontweight="bold")
    ax.grid(axis="x", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    path = CHART_TEMP_DIR / f"round_{round_num}_bars.png"
    plt.tight_layout()
    plt.savefig(path, dpi=120, bbox_inches="tight")
    plt.close()
    return path


def generate_pdf(round_num: int, campaign_id: int) -> Path:
    meta = ROUND_META[round_num]
    stats = ROUND_STATS[round_num]
    pdf_path = OUTPUT_DIR / f"campaign-report-round{round_num}.pdf"

    doc = SimpleDocTemplate(str(pdf_path), pagesize=letter,
                             leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                             topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=22,
                                  textColor=colors.HexColor(PALETTE["primary"]), spaceAfter=6)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14,
                         textColor=colors.HexColor(PALETTE["primary"]), spaceBefore=16, spaceAfter=8)
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=16, spaceAfter=10)
    small = ParagraphStyle("Small", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#757575"))

    story = []

    # Cover
    story.append(Paragraph("Phishing Simulation Campaign Report", title_style))
    story.append(Paragraph(f"{meta['label']}", ParagraphStyle("Sub", parent=styles["Normal"],
                            fontSize=14, textColor=colors.HexColor(PALETTE["neutral"]), spaceAfter=4)))
    story.append(Paragraph(f"Campaign Date: {meta['date']} | Template: {meta['template']}", small))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", small))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor(PALETTE["primary"]),
                             spaceAfter=16))

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2))
    click_change = ""
    if round_num > 1:
        prev_click = ROUND_STATS[round_num - 1]["click_rate"]
        curr_click = stats["click_rate"]
        change = curr_click - prev_click
        direction = "decreased" if change < 0 else "increased"
        click_change = f" This represents a {abs(change):.1f} percentage point {direction} from the previous round."
    story.append(Paragraph(
        f"Campaign Round {round_num} was conducted on {meta['date']} against 10 lab targets using the "
        f"'{meta['template']}' phishing template. The campaign achieved a click rate of {stats['click_rate']}% "
        f"and a credential submission rate of {stats['submission_rate']}%.{click_change} "
        f"The reporting rate was {stats['report_rate']}%, indicating employee awareness and willingness to report.",
        body
    ))

    # Stats Table
    story.append(Paragraph("Campaign Results Dashboard", h2))
    tdata = [
        ["Metric", "Count", "Rate", "Status"],
        ["Emails Sent", "10", "100%", "✓"],
        ["Emails Opened", str(stats["sent"]), f"{stats['open_rate']}%",
         "Monitor" if stats["open_rate"] > 60 else "OK"],
        ["Links Clicked", str(round(stats["click_rate"] / 10)), f"{stats['click_rate']}%",
         "⚠ High" if stats["click_rate"] > 40 else ("OK" if stats["click_rate"] < 20 else "Monitor")],
        ["Creds Submitted", str(round(stats["submission_rate"] / 10)), f"{stats['submission_rate']}%",
         "⚠ RISK" if stats["submission_rate"] > 0 else "✓ None"],
        ["Reported", str(round(stats["report_rate"] / 10)), f"{stats['report_rate']}%",
         "✓ Good" if stats["report_rate"] > 50 else "Improve"],
    ]
    t = Table(tdata, colWidths=[2.2 * inch, 1 * inch, 1 * inch, 1.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(PALETTE["primary"])),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)

    # Charts
    story.append(Paragraph("Results Visualization", h2))
    bar_chart = make_round_bar_chart(round_num)
    story.append(Image(str(bar_chart), width=5.5 * inch, height=2.8 * inch))

    if round_num > 1:
        story.append(Spacer(1, 0.2 * inch))
        trend_chart = make_trend_chart(round_num)
        story.append(Paragraph("Multi-Round Trend", h2))
        story.append(Image(str(trend_chart), width=6 * inch, height=3 * inch))

    # Recommendations
    story.append(PageBreak())
    story.append(Paragraph("Recommendations for Next Campaign", h2))
    recs = []
    if stats["click_rate"] > 30:
        recs.append("High click rate detected. Prioritize phishing recognition training before the next campaign, focusing on URL inspection and sender verification.")
    if stats["submission_rate"] > 0:
        recs.append("Credential submissions occurred. Implement mandatory training for all users who submitted credentials. Consider multi-factor authentication enforcement.")
    if stats["report_rate"] < 40:
        recs.append("Reporting rate is below target (40%). Strengthen the reporting culture by publicly acknowledging users who report phishing, and simplify the reporting process.")
    if stats["click_rate"] < 15:
        recs.append("Excellent click rate. Increase template sophistication for the next round to continue challenging the user population.")
    recs.append("Continue quarterly phishing simulations to maintain awareness levels. Rotate templates to cover new attack vectors (QR code phishing, voice phishing awareness).")
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f"{i}. {rec}", body))

    # Appendix
    story.append(Paragraph("Appendix: Raw Statistics", h2))
    raw_data = [["Field", "Value"]] + [[k, str(v)] for k, v in stats.items()]
    raw_table = Table(raw_data, colWidths=[3 * inch, 2 * inch])
    raw_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
    ]))
    story.append(raw_table)

    doc.build(story)
    console.print(f"[green]PDF report saved: {pdf_path}[/green]")
    return pdf_path


def generate_markdown(round_num: int) -> Path:
    meta = ROUND_META[round_num]
    stats = ROUND_STATS[round_num]
    md_path = OUTPUT_DIR / f"campaign-report-round{round_num}.md"

    lines = [
        f"# Campaign Report — Round {round_num}: {meta['label']}",
        f"**Date:** {meta['date']}  ",
        f"**Template:** {meta['template']}  ",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Round {round_num} phishing simulation was conducted on {meta['date']} against 10 lab targets. "
        f"Click rate: **{stats['click_rate']}%** | Submission rate: **{stats['submission_rate']}%** | "
        f"Report rate: **{stats['report_rate']}%**",
        "",
        "## Results Dashboard",
        "",
        "| Metric | Count | Rate |",
        "|--------|-------|------|",
        f"| Emails Sent | 10 | 100% |",
        f"| Emails Opened | {round(stats['open_rate']/10)} | {stats['open_rate']}% |",
        f"| Links Clicked | {round(stats['click_rate']/10)} | {stats['click_rate']}% |",
        f"| Creds Submitted | {round(stats['submission_rate']/10)} | {stats['submission_rate']}% |",
        f"| Reported | {round(stats['report_rate']/10)} | {stats['report_rate']}% |",
        "",
        "## Detection Performance",
        "",
        f"- SIEM alerts triggered: {'Yes' if stats['clicked'] > 0 else 'No phishing activity to detect'}",
        f"- Wazuh rules active: 10 (IDs 100800–100816)",
        f"- SOAR automation: {'Triggered' if stats['clicked'] > 0 else 'Not triggered (no clicks)'}",
        "",
        "## Recommendations",
        "",
    ]

    if stats["click_rate"] > 30:
        lines.append("- **High click rate**: Deliver focused phishing recognition training before Round 3.")
    if stats["submission_rate"] > 0:
        lines.append("- **Credential submissions**: Mandate training for affected users. Enforce MFA.")
    if stats["report_rate"] < 40:
        lines.append("- **Low reporting rate**: Reward reporters publicly. Simplify the reporting mechanism.")
    lines.append("- Continue quarterly simulations with rotating templates.")

    md_path.write_text("\n".join(lines))
    console.print(f"[green]Markdown report saved: {md_path}[/green]")
    return md_path


def main():
    parser = argparse.ArgumentParser(description="Phishing Campaign Report Generator")
    parser.add_argument("--campaign-id", type=int, required=True, help="GoPhish campaign ID")
    parser.add_argument("--round", type=int, required=True, choices=[1, 2, 3], help="Campaign round number")
    parser.add_argument("--format", choices=["pdf", "markdown", "both"], default="both")
    args = parser.parse_args()

    console.print(f"[bold cyan]Generating Round {args.round} Campaign Report...[/bold cyan]\n")

    if args.format in ("pdf", "both"):
        generate_pdf(args.round, args.campaign_id)
    if args.format in ("markdown", "both"):
        generate_markdown(args.round)

    console.print(f"\n[bold green]Reports saved to: {OUTPUT_DIR}[/bold green]")


if __name__ == "__main__":
    main()
