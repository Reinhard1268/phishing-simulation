# Phishing Awareness Quiz
**Company Security Awareness Program**
**Passing Score: 7/10 (70%)**

---

## Instructions
Read each question carefully and select the best answer. Correct answers with explanations are provided after each question. Complete the quiz honestly — the goal is to learn, not just to pass.

---

## Question 1
You receive an email from `IT-Helpdesk <it-help@company-support-portal.net>` saying your password will expire in 2 hours and you must click a link immediately to reset it. What should you do?

A. Click the link immediately — IT sometimes sends urgent password reset notices.
B. Forward the email to your manager for approval before clicking.
C. Hover over the link to check the URL, verify the sender domain, and if uncertain, contact IT directly via phone or the official portal.
D. Ignore the email and reset your password through the IT portal tomorrow.

**✅ Correct Answer: C**

*Explanation:* The sender domain `company-support-portal.net` is not your company's official domain. Legitimate IT departments send notices from your company's own domain (e.g., `@company.local` or `@company.com`). Always hover over links before clicking and verify urgent requests through official channels — not through the suspicious email itself. Option D has good instinct but doesn't address the fact that this is likely a phishing email that should be reported.*

---

## Question 2
An email arrives from your CEO asking you to urgently wire $47,500 to a new vendor account before end of business today. The email says this is confidential and you should not discuss it with colleagues. What is this most likely?

A. A legitimate urgent business request — CEOs sometimes need quick action.
B. Business Email Compromise (BEC) / CEO fraud — a common phishing attack.
C. A vendor payment workflow that skipped normal approval.
D. A test from HR to see if you follow financial procedures.

**✅ Correct Answer: B**

*Explanation:* This is a textbook Business Email Compromise (BEC) attack. Key red flags: unusual financial request, extreme urgency, request for secrecy, and instruction to bypass normal approval processes. CEOs who have legitimate urgent requests still go through established financial controls. Always verify large financial requests via a direct phone call to the executive using a number you already have — never use contact info from the suspicious email.*

---

## Question 3
You hover over a link in an email that claims to be from Canada Post. The link shows: `http://canadapost-delivery.track-parcel.xyz/reschedule`. Is this safe to click?

A. Yes — Canada Post is a legitimate company and the URL looks professional.
B. Yes — the URL contains the words "canadapost" and "delivery" so it's likely real.
C. No — the real Canada Post domain is `canadapost-postescanada.ca` and `.xyz` is a high-risk TLD often used by phishers.
D. No — all package delivery emails are phishing.

**✅ Correct Answer: C**

*Explanation:* Attackers register domains that contain the brand name to appear legitimate. The real Canada Post website is `canadapost-postescanada.ca`. The `.xyz` TLD (along with `.tk`, `.ml`, `.top`, `.click`) is commonly used in phishing because these domains are cheap or free. Even if part of the URL looks familiar, the actual registered domain is what matters — and here it is `track-parcel.xyz`, not Canada Post.*

---

## Question 4
You receive an email with the subject "2024 Benefits Enrollment — Closes Tomorrow." It asks you to log in with your company credentials to select your benefits. How can you verify whether this is legitimate?

A. Check whether the sender's email address matches an HR domain you recognize.
B. Hover over the login link and verify it goes to your company's official HR portal domain.
C. Contact HR directly through a known phone number or internal Teams message to verify.
D. All of the above.

**✅ Correct Answer: D**

*Explanation:* When verifying a suspicious email, multiple independent checks are better than one. Checking the sender's domain, inspecting the link destination, and independently verifying with HR through a trusted channel together give you a high degree of confidence. Any single check can be spoofed individually, but all three together are very reliable.*

---

## Question 5
You accidentally clicked a link in a phishing email and it opened a webpage that looked like your company's IT login portal. You did NOT enter your password. What should you do first?

A. Reboot your computer to clear any potential malware.
B. Change your password immediately from the same computer.
C. Disconnect your computer from the network (Wi-Fi or ethernet) and contact IT Security.
D. Run a full antivirus scan and then continue working normally.

**✅ Correct Answer: C**

*Explanation:* Disconnecting from the network immediately is the most important first action — it prevents any potential malware from communicating with an attacker's server. Do NOT reboot (this can destroy forensic evidence). Do NOT change your password from the potentially compromised machine. Contact IT Security immediately so they can investigate the endpoint. Even clicking the link without entering credentials can sometimes install malware through browser exploits.*

---

## Question 6
Which of the following is the BEST indicator that an email is a phishing attempt?

A. The email contains a company logo.
B. The Reply-To address is different from the From address, and it leads to a free email service like Gmail.
C. The email was sent outside of business hours.
D. The email has a footer with an unsubscribe link.

**✅ Correct Answer: B**

*Explanation:* A mismatched Reply-To address — especially one redirecting to a personal email service like Gmail or Yahoo when the From address shows a corporate domain — is a strong phishing indicator. It means the attacker controls the Reply-To address and wants to intercept your response. Logos (A) are easily copied. Time of send (C) is irrelevant. Unsubscribe links (D) are present in both legitimate and malicious emails.*

---

## Question 7
Your colleague receives an email from "HR Benefits" with an attachment called `2024-Benefits-Summary.pdf.exe`. What type of attack is this?

A. A legitimate HR document in PDF format.
B. A double-extension attack — the file appears to be a PDF but is actually an executable.
C. A compressed archive file that HR uses to send multiple documents.
D. A virus scanner false positive — `.exe` files can contain PDFs.

**✅ Correct Answer: B**

*Explanation:* This is a double-extension attack. Attackers name files like `document.pdf.exe` knowing that Windows often hides known file extensions, making this appear as `document.pdf` to many users. The actual file type is an executable (`.exe`) — running it could install malware. Real HR documents arrive as `.pdf`, `.docx`, or `.xlsx` — never `.exe`. Report this to IT immediately and do not open it.*

---

## Question 8
An email asks you to "verify your identity" by entering your username and password on a webpage. The page uses HTTPS (the padlock icon is showing in your browser). Does HTTPS mean the site is safe?

A. Yes — HTTPS means the website is verified and legitimate.
B. Yes — the padlock means the site has been checked by security authorities.
C. No — HTTPS only means your connection to the site is encrypted. It does not verify that the site itself is legitimate or not phishing.
D. No — all phishing sites use HTTP, never HTTPS.

**✅ Correct Answer: C**

*Explanation:* This is one of the most common misconceptions about web security. HTTPS (the padlock icon) only means that the data between your browser and the server is encrypted — it says nothing about whether the server belongs to who it claims to be. Attackers can and do obtain free SSL certificates for phishing sites. Always verify the domain itself, not just the presence of a padlock.*

---

## Question 9
You receive a voicemail saying there is suspicious activity on your company account, and you must call back a number urgently. This is an example of what type of attack?

A. Smishing — SMS-based phishing.
B. Vishing — voice-based phishing (phone phishing).
C. Spear phishing — a targeted email attack.
D. Whaling — an attack targeting executives.

**✅ Correct Answer: B**

*Explanation:* Vishing (voice phishing) uses phone calls or voicemails to impersonate trusted organizations — banks, IT departments, government agencies — to pressure victims into revealing sensitive information or taking harmful actions. Never call back a number left in an unsolicited voicemail. If you believe it might be genuine, look up the company's official number independently and call that instead.*

---

## Question 10
Your organization conducts regular phishing simulations. An employee clicks on a simulated phishing link. What is the BEST organizational response?

A. Terminate the employee — they are a security liability.
B. Do nothing — everyone makes mistakes and it was only a simulation.
C. Assign the employee targeted security awareness training and follow up with a re-test within 30 days.
D. Put the employee on a public "watch list" to shame them into being more careful.

**✅ Correct Answer: C**

*Explanation:* The purpose of phishing simulations is to identify training gaps and reduce risk — not to punish employees. Research consistently shows that targeted, timely training immediately following a simulated click produces the greatest improvement in employee behaviour. Public shaming (D) damages morale and actually makes employees less likely to report real phishing incidents out of fear. Doing nothing (B) misses the learning opportunity.*

---

## Scoring Guide

| Score | Result | Next Steps |
|-------|--------|-----------|
| 9–10 / 10 | ✅ Excellent | You are a phishing-aware employee. Share what you know with your team. |
| 7–8 / 10 | ✅ Pass | Review the questions you missed in the awareness guide. |
| 5–6 / 10 | ⚠️ Borderline | Review the full phishing awareness guide and retake within 1 week. |
| 0–4 / 10 | ❌ Fail | Mandatory full training session required. Contact your manager. |
