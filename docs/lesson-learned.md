# Lessons Learned: Enterprise Phishing Simulation & Automated Defense
**Author:** Amoah Reinhard
**Updated Date:** March 2026

---

## Overview

This document captures observations, insights, and recommendations derived from conducting three phishing simulation campaigns against a 10-person lab environment over Q1 2024. It is intended to serve as reference material for designing enterprise phishing simulation programs and improving security posture.

---

## 1. Which Phishing Themes Were Most Effective and Why

### Most Effective: Office 365 MFA Update (70% click rate)

The Microsoft 365 MFA theme produced the highest click and submission rates by a significant margin. The psychological mechanisms at play:

**Authority:** Microsoft is a universally recognized brand. The use of the official Microsoft blue colour scheme, realistic Segoe UI typography, and the square Microsoft logo triggered instant brand recognition and trust.

**Loss aversion:** The threat of account suspension activates loss aversion — a well-documented cognitive bias where people are more motivated to avoid a loss than to achieve a gain of equal value. "Losing access to your account" is perceived as more threatening than a potential gain.

**Uncertainty reduction:** MFA is relatively new to many users. Many users do not have a clear mental model of how MFA updates work, so a notification that their "MFA method is outdated" creates genuine confusion that motivates action rather than skepticism.

**Timing familiarity:** Users regularly receive legitimate Microsoft security notifications. The phishing email matched this existing mental category too closely to trigger suspicion.

### Moderately Effective: IT Password Expiry (30% click rate)

Still effective post-training, but less so. Password expiry notifications are so common that some users have been conditioned to act immediately — creating vulnerability. However, this theme is also better-known as a phishing vector, so trained users recognized it faster.

### Least Effective: HR Benefits Enrollment (10% click rate)

Least effective for several reasons: users were on high alert after two prior campaigns, the SIEM had been tuned to detect and block the phishing domain, and benefits enrollment is a less time-pressured topic than account credential security for most users. The one click that occurred came from the lowest-scoring quiz user.

---

## 2. Which Defenses Worked vs. Failed

### What Worked

**Wazuh Rule 100805 (User Clicked Phishing URL):** This rule fired within 3 minutes of the Round 3 click event and triggered the Shuffle SOAR workflow, which created a TheHive case and sent a Slack alert before any credential submission could occur. This was the most operationally valuable detection in the entire program.

**Shuffle SOAR Integration (Project 3):** The automated response chain (Wazuh alert → Shuffle webhook → TheHive case → Slack notification → GoPhish enrichment) produced a 93.6% reduction in mean time to detect from Round 1 to Round 3. Automation eliminated the latency of human review for the initial triage step.

**User reporting:** By Round 3, 6/10 users reported the phishing email before any automated detection fired on their specific event. User reporting provided near-real-time alerting that predated even the automated SIEM pipeline for most victims.

**DKIM/SPF awareness training:** After specifically covering email authentication in the Round 2 training materials, several users cited the "mismatched sender domain" as their detection method when explaining their Round 3 reports.

### What Failed (Initially)

**Wazuh keyword rules (Round 1):** The initial urgency keyword rule (100800) had a 38% false positive rate because it matched too broadly against normal internal emails. This was resolved between Rounds 1 and 2 by adding domain whitelisting.

**Proxy logging coverage:** In Round 1, the proxy logs did not capture POST request bodies, meaning credential submissions were not visible in Elastic until the GoPhish results API was manually checked. This was a logging configuration gap, not a rule gap. Enabling SSL inspection and deep content inspection on the proxy resolved this for Round 3.

**No alert on email delivery:** The email gateway did not generate Wazuh-parseable logs for inbound phishing emails in the initial configuration, meaning the first alert was not triggered until a user clicked — not when the email arrived. Implementing the email-gateway-decoder.xml and the corresponding rules closes this gap.

---

## 3. How SIEM Detection Improved Across Rounds

| Round | Rules Active | True Positive Rate | False Positive Rate | Mean Time to Detect |
|-------|-------------|-------------------|---------------------|-------------------|
| Round 1 | 2 basic | 40% | 38% | 47 minutes |
| Round 2 | 8 rules | 74% | 18% | 22 minutes |
| Round 3 | 16 rules | 92% | 8% | 3 minutes |

The 92% true positive rate in Round 3 was achieved through iterative rule tuning across two cycles. Each round exposed a gap; each gap became a new rule. This is the core workflow of detection engineering.

The most impactful single change was adding proxy-based click detection (Rule 100805) — moving detection from a keyword scan of email metadata to an actual behavioural signal (user action).

---

## 4. User Behaviour Patterns Observed

**Rapid clickers:** Three users (James, Aisha, Luc) consistently clicked within 10 minutes of email delivery. This "rapid click" pattern suggests low email inspection habits — reading just enough to understand the call-to-action before engaging. These users benefited most from the "pause before you click" training technique.

**IT-aware resistance:** Kevin (IT Support) recognized and reported all three phishing emails, often within minutes of delivery. His Round 1 quiz score (75%) was the highest. Technical role awareness translates directly to better phishing resistance.

**Improvement through repetition:** Sandra and David both clicked in Round 1, neither clicked in Round 2 or 3, and both became active reporters by Round 3. This demonstrates that experienced simulation failure — especially when followed by immediate training — is an effective learning mechanism.

**Persistent vulnerability:** Aisha clicked in all three rounds (though never submitted credentials after Round 1). One user clicking across all rounds despite training suggests a training delivery issue, not a training content issue. A one-on-one session is more effective for this profile than group training.

---

## 5. Recommendations for Real Enterprise Programs

### Optimal Campaign Frequency

Run phishing simulations **quarterly** (every 3 months) for the first year, then **semi-annually** once baseline click rates are below 10% and reporting rates are above 70%. More frequent than quarterly risks simulation fatigue and moral resentment. Annual simulations are insufficient — awareness degrades significantly over 6–12 months.

### Template Diversity Importance

Use at least 4–6 distinct template themes per year, cycling through: credential/account alerts, IT infrastructure (password/MFA), HR processes, executive impersonation (BEC), and delivery/logistics. No single employee role or mental model should be tested more than twice consecutively with the same theme. Employees inoculate against specific patterns after 2–3 exposures.

### Training Timing vs. Simulation Timing

Deliver targeted awareness training **immediately** after a simulation — not weeks later. Research shows that training delivered within 24 hours of a simulated click produces a 60% higher retention rate than training delivered at a scheduled time independent of simulation events. The "teachable moment" effect is real and time-sensitive.

### Metrics That Matter Most

1. **Reporting rate** (most important) — measures security culture, not just individual awareness
2. **Credential submission rate** — measures actual organizational risk exposure
3. **Time-to-report** — measures operational value of the human sensor layer
4. **Click rate** — useful but often overfocused; a non-reporter who doesn't click adds less value than a reporter who recognizes the threat

Avoid treating click rate as the only metric. Organizations with 5% click rates and 5% reporting rates are not materially safer than those with 20% click rates and 70% reporting rates — the second profile has a far more responsive human detection layer.

---

## 6. What Would Be Done Differently

**Instrument the email gateway from Day 1.** The most significant gap in Round 1 was the absence of parsed email gateway logs in Wazuh. Deploying email-gateway-decoder.xml before the first campaign would have provided alerting at delivery time rather than click time.

**Run a baseline quiz before the first campaign.** The pre-training quiz scores were collected alongside Round 1 results, but it would have been cleaner to administer the quiz one week before the first campaign to avoid any priming effect from the simulation itself.

**Include a "did not open" analysis.** Three users never opened the Round 3 email. Understanding whether this was due to pre-delivery filtering (Wazuh blocking the email gateway), changed email habits, or genuine avoidance provides valuable data about the effectiveness of technical controls vs. user behaviour.

**Test the BEC template (CEO Wire Transfer) against Finance roles specifically.** The CEO wire transfer template was included in the portfolio but not deployed in a campaign due to the small lab size. In a real enterprise engagement, this template should be targeted specifically at Finance, Operations, and Executive Assistant roles — the roles most likely to encounter BEC attacks in practice.

**Measure retention decay.** A 6-month follow-up simulation after the program's completion would quantify how quickly awareness degrades without continued reinforcement — providing data to justify ongoing program investment to management.
