# 7. Use-case mapping

| | |
|---|---|
| **Document** | CyberDome for NAM - review pack, document 7 of 9 (for the customer presentation) |
| **Answers** | NAM's challenges, the CyberDome capability that addresses each, and the expected benefit - stated without figures until the pilot measures them |

## 7.1 Seeing the estate

| Challenge | Capability | Expected benefit | Status |
|---|---|---|---|
| Not knowing which devices miss the EDR agent, the DLP agent or disk encryption | **Dome Graph**: every AD baseline device checked against each control; missing, silent, off, unknown; ranked by the personal data on them | one list of gaps, riskiest first, instead of reconciling four consoles | Implemented (fake mode) |
| Devices a tool sees that AD does not; people in no DLP policy group | listed separately on the same screen | baseline drift found before it becomes a blind spot | Implemented |
| A tool quietly failing (agents silent, sync jobs failing, certificates expiring, directory import dropping people) | **Dome Connect - tool health**: findings from each tool's own reports, warned ahead, each with its next step | outages found by the platform, not by users | Implemented (where the tool reports it) |
| Changes to tool configuration nobody recorded | **Change baseline**: daily snapshots, before / after a change with the Dome Score, unplanned changes flagged | a change and its effect on posture on record | Implemented (where the tool exports it) |

## 7.2 Handling DLP alerts

| Challenge | Capability | Expected benefit | Status |
|---|---|---|---|
| A large DLP queue, most of it benign | **Computed disposition**: a published decision table closes the clearly benign (internal, partner, sanctioned; no bulk personal data; no risky sign-in), escalates the clearly risky, asks a person about the rest | analysts spend time where the facts are unclear | Implemented |
| Context spread across tools | facts per alert from Silverfort, Trend Micro, Trellix and the directory; an investigator runs read-only look-ups | the alert arrives investigated | Implemented |
| Using AI without losing control | **Earned autonomy**: shadow → recommend → decide per decision type, on NAM's target, with a second lead; automatic demotion | AI help that grows only as fast as it proves itself | Implemented (shadow, recommend) |
| Insiders trying to talk their way out of an alert | facts, not text: the message is fenced data and read by no rule | an alert cannot be argued away | Implemented |
| Noisy rules | **Rule changes**: suggestions from analysts' rulings, classification quality (OCR, EDM, fingerprints), previewed on past alerts, refused when unsafe, made by an engineer and verified | fewer false positives without hiding real loss | Implemented |

## 7.3 One person, several tools

| Challenge | Capability | Expected benefit | Status |
|---|---|---|---|
| A risky sign-in, a data leak and an unencrypted laptop seen as three unrelated alerts | **Cross-tool cases**: one case per person; severity from how many tools agree | the real incident found as one story | Implemented (privileged check-outs when Arcon is connected) |
| Fast, safe response | revoke sessions and require MFA recommended; isolation when three or more tools agree, always by two people | response prepared, still decided by people | Implemented (actions are placeholders until APIs are confirmed) |

## 7.4 Reporting to the CISO and the board

| Challenge | Capability | Expected benefit | Status |
|---|---|---|---|
| No single posture number the CISO trusts | **Dome Score**: a published formula over computed factors; adjustable weights agreed with the CISO (two leads); not measured is not zero | one number that can be recomputed by hand | Implemented |
| "Why did it drop?" | movement per domain and what would raise it most, from the formula's own factors | answers in seconds, not a week of analysis | Implemented |
| Board reporting effort | the monthly board deck and weekly CISO brief from the same figures | reports that match the screens | Implemented |

## 7.5 Regulation

| Challenge | Capability | Expected benefit | Status |
|---|---|---|---|
| Showing SEBI CSCRF, DPDP and CERT-In evidence | **Dome Comply**: controls mapped to computed evidence tests; the share with current evidence; gaps named; never "compliant" | evidence ready for the auditor | Implemented (catalogue draft to validate) |
| Reportability decisions under time pressure | a breach assessment per personal-data case; a person decides; clocks from the catalogue; the AI drafts | the decision and the draft in one place, on record | Implemented (deadlines to confirm) |
| Audit requests | the audit pack: controls, assessments, catalogue, the full tamper-evident trail | one download | Implemented |

## 7.6 Proving value

| Challenge | Capability | Expected benefit | Status |
|---|---|---|---|
| Knowing whether the pilot worked | **Pilot scorecard**: KPIs against NAM's week-2 baseline and targets NAM sets | a decision on evidence | Implemented |
