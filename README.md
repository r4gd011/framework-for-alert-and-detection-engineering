# FADE — Framework for Alert & Detection Engineering

---

## About This Repository

This is my attempt at a detection engineering framework. Shoutout to Palantir for guidance in its creation.

---

## Framework for Alert & Detection Engineering

With working out of a very large Excel Spreadsheet becoming cumbersome and time consuming, I decided to create a detection framework repo, where I could share detection ideas, and the thought process that went behind them.

FADE provides a consistent, structured approach to writing, documenting, and sharing security detections. Each detection lives in its own Markdown file inside the [`FADE-Examples/`](./FADE-Examples/) folder and follows the template defined in [`FADE.md`](./FADE.md).

---

## FADE Sections

Each detection file is dynamic — sections should be populated with as much information and detail as possible. The following sections make up every FADE detection:

---

### Detection Name

The name of this detection. It aligns directly with the filename of the corresponding `<detection_name.md>` file in the [`FADE-Examples/`](./FADE-Examples/) folder. Names should be informative and succinct, targeting a singular behavior or event (e.g., `Suspicious_PowerShell_Execution.md`).

---

### Purpose

A plain-language description of what this detection is attempting to identify. This section should also document any **blind spots** and **assumptions** baked into the detection — including recognized gaps where the detection may not fire, and adversarial conditions under which it could be defeated.

---

### Attack Mapping

All detections are mapped to the [MITRE ATT&CK Framework](https://attack.mitre.org/). This section includes the relevant tactic and technique, with a direct hyperlink to the corresponding ATT&CK technique page. This enables gap analysis across the kill chain and provides a common language for describing attacker behavior.

**Format:**
- **Tactic:** `<Tactic Name>`
- **Technique:** [`T####.### — <Technique Name>`](https://attack.mitre.org/techniques/T####/)

---

### Alerting and Detection Approach

The technical core of the detection. This section covers the pertinent platforms, processes, tools, data sources, log fields, query logic, and detection objects involved. It should be detailed enough that a responder or engineer can understand exactly how the alert fires without needing to consult a subject matter expert.

---

### Threat Object Context

A deeper look at the threat being detected:
- What is the threat object?
- How does the attack work, step by step?
- Why is this a threat to the environment?
- Tips for investigation — what to look for, pivot points, and context clues that distinguish malicious from benign.

---

### Assumptions and Known False Positives

Documents known instances where this detection may fire incorrectly due to misconfiguration, environmental idiosyncrasies, or non-malicious behavior. Each false positive scenario should include defining characteristics and, where applicable, environment-specific notes. Strategies for minimizing false positives include:

- Adding additional detection rule components to narrow scope
- Filtering out common benign patterns
- Backend suppression for expected false positive sources

---

### Testing & Validation

Step-by-step instructions for generating a representative true positive event to validate the detection is working as intended. This is the unit test for the alert — it must prove that a true positive will be caught. Acceptable formats include:

- Manual walkthroughs
- Scripts (e.g., [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team))
- Proof-of-concept (POC) commands or code snippets
- Orchestration platform scenarios

---

### Severity

The default severity for every new FADE detection is **Medium**. Severity levels are:

| Level | Description |
|-------|-------------|
| Informational | Context only; no immediate action required |
| Low | Suspicious but unlikely to indicate active compromise |
| **Medium** | **Default — warrants investigation** |
| High | Strong indicator of compromise; escalate promptly |
| Critical | Confirmed or near-certain active threat; immediate response required |

---

### Detection Response

What actions should the responding analyst take when this alert fires? This section serves as an **Incident Response playbook** scoped to this specific detection. It should include:

- Initial triage steps
- Key data points to collect
- Escalation criteria
- Containment and remediation guidance
- Communication requirements

---

### References

Credit to sources, research, blog posts, tools, or prior art used to create or inform this detection. All external references should include a title and URL.

---

## Repository Structure

```
fade-framework/
├── README.md           # This file — project overview and section guide
├── FADE.md             # Detection template — copy this to create a new detection
├── LICENSE             # MIT License
└── FADE-Examples/      # Individual detection files
    └── Detection_Name.md
```

---

## License

MIT License

Copyright (c) 2026 r4gd011

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
