# Campaign Comparison Analysis
**Enterprise Phishing Simulation & Automated Defense**

---

## Program Overview

Three phishing simulation campaigns were conducted over Q1 2024 against a 10-person lab target group. Campaigns were spaced approximately 4 weeks apart, with security awareness training and SIEM tuning occurring between each round.

---

## Campaign Summary Table

| Metric | Round 1 | Round 2 | Round 3 | Change R1→R3 |
|--------|---------|---------|---------|-------------|
| Sent | 10 | 10 | 10 | — |
| Opened | 9 (90%) | 7 (70%) | 4 (40%) | ↓ 55.6% |
| Clicked | 7 (70%) | 3 (30%) | 1 (10%) | ↓ 85.7% |
| Submitted | 4 (40%) | 1 (10%) | 0 (0%) | ↓ 100% |
| Reported | 1 (10%) | 4 (40%) | 6 (60%) | ↑ 500% |

---

## Trend Analysis

### Click Rate Progression
The click rate dropped dramatically across all three campaigns:
- Round 1 → Round 2: 70% → 30% (57% reduction) — driven primarily by the awareness training completed between campaigns
- Round 2 → Round 3: 30% → 10% (67% reduction) — driven by both repeated training and SIEM-based active blocking of the phishing domain upon the first click

The trajectory is consistent with published industry research: targeted phishing simulation with immediate follow-up training produces the greatest single-campaign improvement.

### Credential Submission Rate
Reaching zero credential submissions in Round 3 is the most significant result. This metric represents actual organizational risk — stolen credentials are the primary entry point for account takeover, data breaches, and ransomware attacks.

### Reporting Rate Growth
The reporting rate improvement from 10% to 60% represents a fundamental cultural shift. In a real-world scenario, a 60% reporting rate means the SOC would receive actionable alerts from users within minutes of a campaign launch — dramatically reducing dwell time and containment complexity.

---

## Template Effectiveness Analysis

The three templates were tested across three rounds. Key observations:

**Office 365 MFA Update (Round 1) — 70% click, 40% submission**
The most effective template. MFA-related urgency combined with realistic Microsoft branding and a genuine fear trigger (losing account access) produced the highest engagement. This aligns with industry data showing that credential/account templates consistently outperform generic phishing themes.

**IT Password Expiry (Round 2) — 30% click, 10% submission**
Moderately effective even post-training. Password expiry is a familiar, routine IT communication — users have been conditioned to act on these messages. The reduction from Round 1 reflects training impact rather than a weaker template.

**HR Benefits Enrollment (Round 3) — 10% click, 0% submission**
Lowest effectiveness, likely because: (a) users were more aware after two prior campaigns, (b) SIEM rules actively blocked the domain on the first click event, and (c) the HR benefits theme is less time-pressured than credential/account themes for most users.

---

## Most Vulnerable User Segments

Analysis of who clicked across multiple rounds reveals role-based patterns:

- **Finance roles** (Accountant, Finance Manager): High susceptibility to authority/urgency themes, especially credential requests tied to financial systems
- **Marketing roles**: High email volume in daily work creates habitual clicking patterns — users are desensitized to urgency due to marketing email conventions
- **Operations/Sales roles**: Lower technical security awareness compared to IT/Legal/Developer roles

**Resistant segments:** IT Support, Software Developer, and Legal Counsel demonstrated significantly higher resistance — likely due to greater baseline security awareness from job-related exposure.

---

## Benchmarks vs. Industry Averages

| Metric | This Program (R3) | Industry Average | Delta |
|--------|------------------|-----------------|-------|
| Click Rate (post-training) | 10% | 35% | **↓ 25 points better** |
| Reporting Rate (mature) | 60% | 55% | **↑ 5 points better** |
| Submission Rate | 0% | 8% | **↓ 8 points better** |

This program's results exceed industry benchmark averages for post-training metrics, suggesting the combination of realistic campaigns, targeted training, and SIEM-integrated detection is more effective than training alone.

---

## Improvement Trajectory

Projecting forward based on Round 1→3 improvement rates:

- A Round 4 campaign would likely achieve a click rate of 5% or below
- Reporting rate could reach 80%+ with continued positive reinforcement of reporters
- Key risk: without continued simulation, metrics degrade over 6–12 months (human memory decay)

**Recommendation:** Maintain quarterly simulations permanently. Vary templates with new themes each quarter to prevent inoculation against specific patterns.
