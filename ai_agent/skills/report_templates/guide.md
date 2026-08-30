# Pentest Report Templates & Writing Standards

A pentest report is a professional deliverable: it must be readable by executives,
actionable by engineers, and defensible by auditors. Follow this structure and the
per-finding template below. Use the findings log (`add_finding` / `update_finding` /
`write_report`) as the source of truth and generate the final Markdown report from it.

## Report Structure (top-level)

1. **Cover / Metadata** — client, assessor, date range, classification, engagement
   ID, targets, methodology reference, and sign-off.
2. **Executive Summary** — plain-language overview: what was tested, headline risks
   (top 3-5 findings), overall risk posture, and what must be fixed first.
   No jargon; assume a non-technical reader. Include a severity distribution table.
3. **Scope & Methodology** — in-scope assets, out-of-scope exclusions, tools used,
   and the staged methodology (recon → enumeration → vulnerability mapping →
   PoC validation → remediation). Mention authorization references.
4. **Findings Register** — one section per finding, ordered by severity
   (Critical > High > Medium > Low > Info). Each finding uses the template below.
   Add an executive summary table: ID | severity | CVSS | CWE | affected asset |
   status (confirmed / needs-validation / false-positive).
5. **Technical Appendix** — full raw evidence: requests/responses, payloads, logs,
   scan extracts, screenshots, and reproduction commands.
6. **Remediation Roadmap** — prioritized fix plan (quick wins vs. architectural),
   with effort estimates per item.

## Per-Finding Template

```markdown
### [F-01] <Short descriptive title>

- **Severity:** Critical | High | Medium | Low | Info
- **CVSS:** X.X (vector: CVSS:3.1/AV:...)
- **CWE:** CWE-### (<name>)
- **Affected asset:** <host/URL/endpoint>
- **Status:** Confirmed | Needs-validation | False-positive
- **Confidence:** High | Medium | Low

**Description**
<What the weakness is, in one paragraph, and why it matters.>

**Evidence**
<Request/response excerpts, payload used, tool output, screenshot ref.>

**Reproduction steps**
1. <step>
2. <step>

**Impact**
<What an attacker can actually do — demonstrated blast radius, not theoretical.>

**Remediation**
<Specific, actionable fix: code change, config, control, and verification step.>

**References**
<CVE advisory, OWASP, vendor doc links.>
```

## Severity Calibration Rules

- Base severity on the **demonstrated** impact, not the theoretical worst case.
- Account honestly for prerequisites (auth required? attacker position? interaction?).
- RCE / SQLi / auth bypass with evidence → Critical (CVSS >= 9.0 typically).
- XSS, SSRF with limited reach, medium-risk IDOR → High/Medium by actual impact.
- Missing headers, verbose errors, low-risk info leaks → Low/Info.
- Cannot reproduce impact → label "hypothesis / needs-validation", never confirmed.
- Deduplicate: one finding per root cause, not one per endpoint.

## Verification Status Tags (mandatory)

- `[VERIFIED TRUE POSITIVE]` — reproduced with distinguishing evidence.
- `[UNVERIFIED / REQUIRES MANUAL AUDIT]` — plausible but not fully proven.
- `[FALSE POSITIVE - FILTERED]` — tested and rejected; keep only in the appendix
  with the rejection reason.

## Final-Answer Style (chat-level summary)

When the user did not ask for a full report, end with a compact summary:
- What was tested and the attack surface covered.
- Findings table (ID | severity | asset | one-line issue).
- Top remediation priorities (2-3 items).
- Any open items / needs-validation.
