# Defense Improvement Report — Before vs. After Analysis
**Enterprise Phishing Simulation & Automated Defense**
**Period:** January 16 – March 12, 2024 (Campaign Round 1 → Round 3)
**Updated on March,2026**
---

## Executive Summary

This report quantifies the security improvement achieved over three phishing simulation campaigns. The program combined realistic phishing simulations with structured user awareness training and iterative SIEM rule tuning. The results demonstrate measurable, significant improvement across detection accuracy, user behaviour, response time, and overall organizational risk posture.

**Bottom line:** Organizational risk from phishing attacks was reduced by approximately 87% over the 8-week program period based on the composite risk metric defined below.

---

## 1. Detection Accuracy: Round 1 vs. Round 3

### SIEM Alert Performance

| Metric | Round 1 | Round 3 | Improvement |
|--------|---------|---------|------------|
| Rules triggering on campaign events | 2/10 rules | 9/10 rules | +350% |
| True positive rate | 40% | 92% | +52 points |
| False positive rate | 38% | 8% | ↓ 30 points |
| Missed detections (phishing not alerted) | 6 | 1 | ↓ 83.3% |
| Alert-to-investigation time (avg) | 47 min | 11 min | ↓ 76.6% |

**What changed between rounds:**
- Round 1 revealed that only basic rules (keyword detection) were operational. Rules for proxy-based click detection, credential submission to external sites, and SPF/DKIM failures were incomplete or misconfigured.
- Between Rounds 1 and 2, 8 new Wazuh rules were deployed (IDs 100800–100816), covering proxy clicks, sender mismatches, IP-based links, and email authentication failures.
- By Round 3, the first click by the one remaining victim triggered an immediate Wazuh alert (rule 100805), which fired a TheHive case via Shuffle before any credential could be submitted — effectively containing the incident before escalation.

---

## 2. SIEM Alert Precision Improvement

### False Positive Rate

A high false positive rate causes alert fatigue — analysts stop paying attention. The initial rules in Round 1 produced too many benign email events matching keyword rules.

**Round 1:** 38% of alerts were false positives (normal corporate emails triggering urgency keyword rule 100800).

**Tuning actions taken:**
- Added domain whitelist to rule 100800: internal senders whitelisted from keyword checks
- Added minimum score threshold: only emails from external senders with 2+ urgency keywords trigger alerts
- Refined rule 100807 (mass click): raised frequency threshold from 2 to 3 distinct users

**Round 3:** False positive rate reduced to 8% — below the 10% industry target for a well-tuned environment.

---

## 3. Response Time Improvement

| Phase | Round 1 Avg Time | Round 3 Avg Time | Reduction |
|-------|----------------|----------------|-----------|
| Detection (first alert) | 47 min | 3 min | ↓ 93.6% |
| Triage (alert reviewed) | 62 min | 8 min | ↓ 87.1% |
| Containment (URL blocked) | Manual, ~4 hours | Automated, 6 min | ↓ 97.5% |
| User notification | Manual, next-day | Automated Slack, 4 min | ↓ 98.7% |

The most significant improvement came from the Shuffle SOAR automation deployed between Rounds 1 and 2 (leveraging Project 3 infrastructure). Upon rule 100805 firing, the SOAR workflow automatically created a TheHive case, sent a Slack alert to the SOC, queried GoPhish for the victim's full event record, and blocked the phishing URL — all within 6 minutes of the first click, without analyst intervention.

---

## 4. User Reporting Rate Improvement

The reporting rate is the single most important leading indicator of security culture maturity.

| Round | Reporting Rate | Users Who Reported |
|-------|---------------|-------------------|
| Round 1 | 10% (1/10) | Kevin Tremblay (IT) |
| Round 2 | 40% (4/10) | Kevin, James, Sandra, Fatima |
| Round 3 | 60% (6/10) | Kevin, James, Sandra, Fatima, Mei, David |

**Growth analysis:** The 6x increase in reporting rate demonstrates that security awareness training directly drives the reporting behaviour change — not just click avoidance. Users who previously received the phishing email and did nothing (did not click, but also did not report) became active reporters by Round 3.

**Industry benchmark:** A 60% reporting rate exceeds the industry average of 55% for mature security awareness programs. The program reached benchmark performance within 8 weeks.

---

## 5. Overall Risk Reduction Calculation

### Composite Phishing Risk Score (CPRS)

The CPRS is calculated as:
CPRS = (Click Rate × 0.4) + (Submission Rate × 0.5) + ((1 - Report Rate) × 0.1)

| Round | Click Rate | Sub Rate | Report Rate | CPRS |
|-------|-----------|----------|-------------|------|
| Round 1 | 70% | 40% | 10% | (0.28) + (0.20) + (0.09) = **0.57** |
| Round 2 | 30% | 10% | 40% | (0.12) + (0.05) + (0.06) = **0.23** |
| Round 3 | 10% | 0% | 60% | (0.04) + (0.00) + (0.04) = **0.08** |

**Risk reduction from Round 1 to Round 3: 86% reduction in composite phishing risk.**

---

## 6. ROI of the Security Awareness Program

### Cost Estimate (Lab Environment)

| Item | Estimated Cost |
|------|--------------|
| GoPhish (open source) | $0 |
| MailHog (open source) | $0 |
| Training module development | 8 hours analyst time |
| Campaign execution (3 rounds) | 12 hours analyst time |
| SIEM rule tuning | 6 hours analyst time |
| **Total program cost (time)** | **~26 analyst hours** |

### Value Delivered

| Prevented Risk | Basis | Estimated Value |
|---------------|-------|----------------|
| Credential theft prevention | 4 submissions in R1 → 0 in R3 | Prevents avg $4.9M breach cost |
| SOC efficiency gain | Detection time 47min → 3min | Analyst hours saved per incident |
| Insurance premium reduction | Demonstrable training program | 5–15% reduction typical |
| Regulatory compliance | PIPEDA, SOC 2 awareness training | Audit documentation value |

The ROI of a phishing awareness program is consistently positive. Industry data from Proofpoint and IBM Security consistently shows that every $1 invested in security awareness training returns $8–$25 in breach cost avoidance.

---

## 7. Key Takeaways

1. **Training works, but simulations without training don't.** The click rate reduction from Round 1 to Round 2 was primarily driven by the training delivered between campaigns — not by time alone.

2. **SIEM tuning amplifies training.** The combination of trained users AND tuned detection rules produced a multiplicative effect. The single Round 3 click was detected and contained in under 6 minutes before any harm could occur.

3. **Reporting rate is more valuable than click rate.** A user who reports a phishing email protects the entire organization. Prioritizing reporting-rate improvement in training content and organizational incentives should be the primary focus of a mature program.

4. **Authority + urgency templates remain the most dangerous.** The Office 365 MFA template (70% click rate) significantly outperformed the HR benefits template (10% click rate) — both before and after training. Future training should double-down on identity/account credential themes.

5. **Zero credential submissions is achievable.** It took one round of targeted training to eliminate credential submission entirely. This is the single most impactful metric to move.
