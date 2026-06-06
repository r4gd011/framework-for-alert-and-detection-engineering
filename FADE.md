# Framework for Alert & Detection Engineering (FADE)

FADE is a structured methodology for creating, documenting, and sharing security detections. Each detection is stored as an individual Markdown file in the [`FADE-Examples/`](./FADE-Examples/) directory and must include all sections defined below. Sections are dynamic — populate each one with as much detail as the detection warrants.

---

## Detection Name

The detection name is a concise, informative title that describes the behavior being detected. It should target a singular event or action (e.g., `Encoded PowerShell Execution`, `LSASS Memory Access via Non-Standard Process`). The name aligns directly with the filename of the corresponding detection file in `FADE-Examples/` and is used as the primary identifier when linking detections from indexes, dashboards, or documentation.

**Naming guidance:**
- Be specific — prefer `Suspicious Scheduled Task Creation via CMD` over `Suspicious Scheduled Task`
- Avoid vague terms like "Anomalous" or "Possible" unless no stronger signal exists
- Use title case
- Name the file using underscores in place of spaces (e.g., `enc_powershell_execution.md`)

---

## Purpose

A plain-language description of what the detection is attempting to identify and why it matters. This section should also document any **blind spots** and **assumptions** baked into the detection logic — including recognized gaps, environmental dependencies, and adversarial conditions under which the detection may fail or be defeated.

**This section should answer:**
- What specific behavior or event does this detection target?
- What data sources, logging configurations, or agent deployments does it depend on?
- Under what conditions will the detection *not* fire — and what would an adversary need to do to evade it?
- What assumptions about the environment are embedded in the logic?

---

## Attack Mapping

All FADE detections are mapped to the [MITRE ATT&CK Framework](https://attack.mitre.org/). This section identifies the relevant tactic and technique and includes a direct hyperlink to the ATT&CK technique page. Consistent mapping enables gap analysis across the kill chain, supports threat-informed prioritization, and provides a shared language for communicating detection coverage to stakeholders.

**This section should include:**
- The ATT&CK Tactic (e.g., Execution, Persistence, Credential Access)
- The ATT&CK Technique and Sub-technique, with link (e.g., [`T1059.001 — PowerShell`](https://attack.mitre.org/techniques/T1059/001/))
- Any related techniques that are adjacent to or commonly paired with this detection

---

## Alerting and Detection Approach

The technical core of the detection. This section covers the platforms, processes, tools, data sources, log fields, and query logic that make the alert function. It must be self-contained — a responder or detection engineer should be able to fully understand how the alert fires without consulting a subject matter expert.

**This section should include:**
- The data source(s) and log channel(s) being monitored (e.g., Sysmon Event ID 1, Windows Security Event 4688, EDR telemetry)
- The platform(s) and tooling involved (e.g., Windows 10+, Splunk, CrowdStrike Falcon)
- Key log fields and indicator values the detection logic acts on
- The detection query or rule logic (SPL, KQL, Sigma, YARA, etc.)
- Any enrichment steps applied to the raw alert before it fires (e.g., asset criticality lookups, threat intel correlation, user context)
- Representative true positive log samples with realistic field values, GUIDs, timestamps, and command lines where applicable

---

## Threat Object Context

A deeper examination of the threat the detection targets. This section provides the technical and contextual knowledge a responding analyst needs to understand what they are looking at, why it is dangerous, and where to focus an investigation.

**This section should answer:**
- What is the threat object — the process, binary, command, technique, or artifact being detected?
- How does the attack work, step by step?
- Why is this a threat to the environment — what is the potential impact if the activity goes undetected?
- What investigation tips, pivot points, and contextual signals help distinguish malicious activity from benign?

---

## Assumptions and Known False Positives

Documents known scenarios where this detection may fire incorrectly due to legitimate software behavior, misconfiguration, or environmental idiosyncrasies. Each false positive scenario should include defining characteristics and, where applicable, environment-specific notes. This section should also describe the strategies used to minimize false positives.

**Common false positive minimization strategies:**
- Add additional detection rule components to narrow scope (e.g., require a second indicator alongside the primary signal)
- Filter out common benign patterns by parent process, signing certificate, or user context
- Configure backend suppression for expected false positive sources (e.g., known service accounts, managed deployment tooling)

---

## Testing & Validation

Step-by-step instructions for generating a representative true positive event to confirm the detection fires correctly. This is the functional equivalent of a unit test for the alert — it must demonstrate that a true positive will be caught. Acceptable formats include manual walkthroughs, PowerShell or Bash scripts, proof-of-concept (POC) commands, and Atomic Red Team tests.

**This section should include:**
- Prerequisites (lab environment, logging configuration, agent requirements)
- Numbered steps to reproduce a true positive event
- The expected result — what the alert looks like when it fires correctly
- A POC command, script, or code snippet where applicable
- A reference to the corresponding [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test if one exists

---

## Severity

The priority level assigned to this detection. The default severity for all new FADE detections is **Medium**. Severity should reflect the fidelity and potential impact of the detection after known false positives have been suppressed.

| Level | Description |
|-------|-------------|
| Informational | Context only; no immediate action required |
| Low | Suspicious but unlikely to indicate active compromise on its own |
| **Medium** | **Default — warrants investigation** |
| High | Strong indicator of compromise; escalate promptly |
| Critical | Confirmed or near-certain active threat; immediate response required |

Each detection file must document the assigned severity and include a rationale explaining why that level was chosen.

---

## Detection Response

Defines the actions a responding analyst should take when this alert fires. This section serves as an Incident Response playbook scoped to the specific detection, containing the common investigation steps, escalation criteria, and remediation actions relevant to this alert.

**This section should include:**
- Initial triage steps to confirm the alert is a true positive
- Key data points and artifacts to collect
- Criteria for escalating to a higher severity
- Containment and remediation steps
- Communication and documentation requirements

The goal is for an analyst who has never seen this detection before to be able to open this section and immediately know what to do.

---

## References

Credits all sources, research, blog posts, vendor documentation, tools, or prior art used to build or inform the detection. Every reference should include a title and URL.

---

*FADE — Framework for Alert & Detection Engineering*
