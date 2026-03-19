#Enterprise Phishing Simulation & Automated Defense
# Generates matplotlib charts from click-rate-tracker.json and saves as PNG + PDF summary

import json
from pathlib import Path
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle

DATA_FILE = Path("metrics/click-rates/click-rate-tracker.json")
OUTPUT_DIR = Path("metrics/click-rates/charts")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PALETTE = {
    "primary": "#1565c0",
    "danger": "#c62828",
    "success": "#2e7d32",
    "warning": "#f57f17",
    "neutral": "#546e7a",
    "light_blue": "#90caf9",
    "light_red": "#ef9a9a",
    "light_green": "#a5d6a7",
}


def load_data() -> dict:
    with open(DATA_FILE) as f:
        return json.load(f)


def chart_click_rate_trend(data: dict) -> Path:
    rounds = data["rounds"]
    labels = [r["label"].replace(" — ", "\n") for r in rounds]
    click_rates = [r["click_rate"] for r in rounds]
    submission_rates = [r["submission_rate"] for r in rounds]
    reporting_rates = [r["reporting_rate"] for r in rounds]
    ci_lower = [r["confidence_interval_95"]["lower"] for r in rounds]
    ci_upper = [r["confidence_interval_95"]["upper"] for r in rounds]
    x = np.array([1, 2, 3])

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")

    ax.plot(x, click_rates, color=PALETTE["danger"], linewidth=3, marker="o", markersize=10,
            label="Click Rate %", zorder=5)
    ax.fill_between(x, ci_lower, ci_upper, alpha=0.15, color=PALETTE["danger"], label="95% CI (click)")

    ax.plot(x, submission_rates, color=PALETTE["warning"], linewidth=2.5, marker="s", markersize=8,
            label="Submission Rate %", linestyle="--")

    ax.plot(x, reporting_rates, color=PALETTE["success"], linewidth=2.5, marker="^", markersize=8,
            label="Reporting Rate %", linestyle="-.")

    for i, (cr, sr, rr) in enumerate(zip(click_rates, submission_rates, reporting_rates)):
        ax.annotate(f"{cr}%", (x[i], cr), textcoords="offset points", xytext=(0, 12),
                    ha="center", fontsize=11, fontweight="bold", color=PALETTE["danger"])
        ax.annotate(f"{rr}%", (x[i], rr), textcoords="offset points", xytext=(0, 12),
                    ha="center", fontsize=10, color=PALETTE["success"])

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Rate (%)", fontsize=12)
    ax.set_ylim(-5, 110)
    ax.set_title("Phishing Campaign Metrics — 3-Round Trend", fontsize=15, fontweight="bold", pad=16)
    ax.legend(fontsize=10, loc="upper right")
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    path = OUTPUT_DIR / "click_rate_trend.png"
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")
    return path


def chart_template_effectiveness(data: dict) -> Path:
    templates = data["template_click_rates"]
    names = [t["template"].replace("-", "\n") for t in templates]
    click_rates = [t["click_rate"] for t in templates]
    submission_rates = [t["submission_rate"] for t in templates]

    x = np.arange(len(names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(11, 6))
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")

    bars1 = ax.bar(x - width / 2, click_rates, width, label="Click Rate %",
                   color=PALETTE["danger"], alpha=0.85, edgecolor="white")
    bars2 = ax.bar(x + width / 2, submission_rates, width, label="Submission Rate %",
                   color=PALETTE["warning"], alpha=0.85, edgecolor="white")

    for bar in bars1:
        if bar.get_height() > 0:
            ax.annotate(f"{bar.get_height():.0f}%",
                        xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=10, fontweight="bold")
    for bar in bars2:
        if bar.get_height() > 0:
            ax.annotate(f"{bar.get_height():.0f}%",
                        xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", va="bottom", fontsize=10)

    ax.set_xticks(x)
    ax.set_xticklabels(names, fontsize=9)
    ax.set_ylabel("Rate (%)", fontsize=12)
    ax.set_ylim(0, 90)
    ax.set_title("Template Effectiveness — Click & Submission Rates by Template", fontsize=14, fontweight="bold", pad=16)
    ax.legend(fontsize=11)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    path = OUTPUT_DIR / "template_effectiveness.png"
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")
    return path


def chart_hour_of_day(data: dict) -> Path:
    hod = data["hour_of_day_clicks"]
    hours = sorted(hod.keys())
    counts = [hod[h] for h in hours]
    hour_labels = [f"{int(h):02d}:00" for h in hours]
    colors_list = [PALETTE["danger"] if c > 0 else "#e0e0e0" for c in counts]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")

    bars = ax.bar(hour_labels, counts, color=colors_list, edgecolor="white", width=0.7)
    for bar in bars:
        if bar.get_height() > 0:
            ax.annotate(str(int(bar.get_height())),
                        xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                        xytext=(0, 4), textcoords="offset points",
                        ha="center", fontsize=11, fontweight="bold")

    ax.axvspan(-0.5, 0.5, alpha=0.06, color="blue")
    ax.set_ylabel("Number of Clicks", fontsize=12)
    ax.set_xlabel("Hour of Day (24h)", fontsize=12)
    ax.set_title("Click Distribution by Hour of Day — All Campaigns", fontsize=14, fontweight="bold", pad=16)
    ax.set_ylim(0, max(counts) + 1.5 if counts else 5)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    path = OUTPUT_DIR / "hour_of_day_distribution.png"
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")
    return path


def chart_submission_vs_click(data: dict) -> Path:
    rounds = data["rounds"]
    labels = [f"R{r['round']}" for r in rounds]
    click_rates = [r["click_rate"] for r in rounds]
    submission_rates = [r["submission_rate"] for r in rounds]

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor("#fafafa")
    ax.set_facecolor("#fafafa")

    x = np.arange(len(labels))
    width = 0.35
    ax.bar(x - width / 2, click_rates, width, label="Click Rate %",
           color=PALETTE["danger"], alpha=0.8)
    ax.bar(x + width / 2, submission_rates, width, label="Submission Rate %",
           color=PALETTE["primary"], alpha=0.8)

    ax.set_xticks(x)
    ax.set_xticklabels([r["label"].split("—")[0].strip() for r in rounds], fontsize=10)
    ax.set_ylabel("Rate (%)", fontsize=12)
    ax.set_ylim(0, 90)
    ax.set_title("Click vs. Credential Submission Rate — Per Round", fontsize=13, fontweight="bold", pad=14)
    ax.legend(fontsize=11)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    path = OUTPUT_DIR / "submission_vs_click.png"
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {path}")
    return path


def generate_pdf_summary(data: dict, chart_paths: list[Path]) -> Path:
    pdf_path = OUTPUT_DIR / "click_rate_summary_report.pdf"
    doc = SimpleDocTemplate(str(pdf_path), pagesize=letter,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=20,
                                  textColor=colors.HexColor("#1565c0"), spaceAfter=8)
    subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=11,
                                     textColor=colors.HexColor("#546e7a"), spaceAfter=20)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=14,
                               textColor=colors.HexColor("#1565c0"), spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10,
                                 leading=16, spaceAfter=10)

    story.append(Paragraph("Phishing Simulation Click Rate Report", title_style))
    story.append(Paragraph(f"Project 08 | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", subtitle_style))

    story.append(Paragraph("Program Summary", h2_style))
    rounds = data["rounds"]
    table_data = [
        ["Round", "Date", "Template", "Click Rate", "Submission Rate", "Report Rate"],
        *[[f"Round {r['round']}", r["date"], r["template"][:20],
           f"{r['click_rate']}%", f"{r['submission_rate']}%", f"{r['reporting_rate']}%"]
          for r in rounds]
    ]
    t = Table(table_data, colWidths=[0.6*inch, 0.9*inch, 1.8*inch, 0.9*inch, 1.1*inch, 0.9*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1565c0")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    for chart_path in chart_paths:
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(chart_path.stem.replace("_", " ").title(), h2_style))
        story.append(Image(str(chart_path), width=6.5 * inch, height=3.8 * inch))

    doc.build(story)
    print(f"PDF saved: {pdf_path}")
    return pdf_path


def main():
    print("Generating phishing simulation charts...")
    data = load_data()
    chart_paths = [
        chart_click_rate_trend(data),
        chart_template_effectiveness(data),
        chart_hour_of_day(data),
        chart_submission_vs_click(data),
    ]
    pdf = generate_pdf_summary(data, chart_paths)
    print(f"\nAll charts saved to: {OUTPUT_DIR}")
    print(f"PDF summary: {pdf}")


if __name__ == "__main__":
    main()
