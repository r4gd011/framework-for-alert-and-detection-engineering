# Detection Name

> This is a starter template. Rename this file to match your detection (e.g., `Suspicious_PowerShell_Execution.md`) and replace all placeholder content below.

---

## Detection Name

**Name:** `Detection_Name`  
**File:** [`Detection_Name.md`](./Detection_Name.md)

---

## Purpose

> Describe what this detection is attempting to identify. Include any blind spots or assumptions baked into the logic — recognized gaps, environmental dependencies, or conditions under which this detection may fail or be defeated by an adversary.

**What this detects:**  
*(e.g., Identifies when a process performs an action commonly associated with credential dumping.)*

**Blind spots / assumptions:**  
- *(e.g., Assumes endpoint logging is enabled and forwarded to SIEM.)*
- *(e.g., Will not fire if the adversary uses a novel, undocumented technique.)*

---

## Attack Mapping

> Map this detection to the MITRE ATT&CK Framework. Include the tactic, technique, and a direct link to the ATT&CK technique page.

| Field | Value |
|-------|-------|
| **Tactic** | `<Tactic Name>` |
| **Technique** | [`T#### — <Technique Name>`](https://attack.mitre.org/techniques/T####/) |
| **Sub-technique** | *(if applicable)* |

---

## Alerting and Detection Approach

> Describe the technical mechanics of the detection. Include relevant platforms, processes, tools, data sources, log sources, key fields, and the detection logic or query. This section should be self-contained — a responder should be able to fully understand the alert without needing a subject matter expert.

**Data Source(s):**  
*(e.g., Windows Event Logs, EDR telemetry, Sysmon)*

**Platform(s) / Tool(s):**  
*(e.g., Windows 10+, Splunk, CrowdStrike Falcon)*

**Key Log Fields / Indicators:**  
*(e.g., EventID 4688, Image, CommandLine, ParentImage)*

**Detection Logic / Query:**

```
<paste detection query, rule, or logic here>
```

**Enrichment Steps:**  
*(e.g., Enrich with user context, asset criticality, and threat intelligence feeds.)*

---

## Threat Object Context

> Explain what is being detected, how the attack works end-to-end, why it is a threat, and any investigative tips that help analysts distinguish malicious activity from benign.

**What is the threat object?**  
*(e.g., A process or binary performing suspicious actions.)*

**How does the attack work?**  
*(Walk through the attack chain step by step.)*

**Why is this a threat?**  
*(Explain the impact if exploited.)*

**Investigation tips / pivot points:**  
- *(e.g., Check parent process, user context, network connections spawned.)*
- *(e.g., Review file system changes in the same timeframe.)*

---

## Assumptions and Known False Positives

> Document known scenarios where this detection may fire incorrectly. Include defining characteristics and environment-specific notes.

**Known false positive scenarios:**

| Scenario | Defining Characteristics | Mitigation |
|----------|--------------------------|------------|
| *(e.g., IT admin running legitimate tool)* | *(e.g., Known admin account, scheduled maintenance window)* | *(e.g., Allowlist by account and source host)* |

**False positive minimization strategies:**
- [ ] Added additional detection components to narrow scope
- [ ] Filtered common benign patterns
- [ ] Backend suppression configured for expected sources

---

## Testing & Validation

> Provide step-by-step instructions for generating a true positive event to confirm the detection fires correctly.

**Prerequisites:**  
*(e.g., Test VM with endpoint agent installed, logging enabled and forwarded.)*

**Steps:**

1. *(e.g., Open an elevated PowerShell session.)*
2. *(e.g., Execute the following command.)*
3. *(e.g., Confirm alert fires in SIEM within X minutes.)*

**Expected result:**  
*(Describe what a successful true positive looks like.)*

**POC / Script:**

```
<paste POC command, script, or Atomic Red Team test here>
```

**Atomic Red Team test (if available):** *(e.g., T1059.001 - Test #1)*

---

## Severity

**Default Severity: Medium**

| Level | Description |
|-------|-------------|
| Informational | Context only; no immediate action required |
| Low | Suspicious but unlikely to indicate active compromise |
| **Medium** | **Default — warrants investigation** |
| High | Strong indicator of compromise; escalate promptly |
| Critical | Confirmed or near-certain active threat; immediate response required |

**Assigned Severity:** `Medium`

**Rationale:**  
*(Explain why this severity level was chosen.)*

---

## Detection Response

> Define the actions a responding analyst should take when this alert fires.

### Initial Triage

1. *(e.g., Confirm the alert is a true positive by reviewing the raw log.)*
2. *(e.g., Identify the affected host and user account.)*
3. *(e.g., Determine if the activity is isolated or part of a broader pattern.)*

### Key Data Points to Collect

- *(e.g., Source host name and IP)*
- *(e.g., User account and privilege level)*
- *(e.g., Parent and child process details)*
- *(e.g., Network connections at time of alert)*

### Escalation Criteria

Escalate to **High / Critical** if:
- *(e.g., Activity is confirmed malicious and data exfiltration is suspected.)*
- *(e.g., Multiple hosts are affected.)*

### Containment & Remediation

1. *(e.g., Isolate the affected endpoint.)*
2. *(e.g., Disable the compromised account.)*
3. *(e.g., Engage incident response team for forensic investigation.)*

### Communication Requirements

- *(e.g., Notify the SOC lead and document findings in the ticketing system.)*

---

## References

| Title | URL |
|-------|-----|
| MITRE ATT&CK | https://attack.mitre.org/ |
| Palantir ADS Framework | https://github.com/palantir/alerting-detection-strategy-framework |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team |

---

*FADE — Framework for Alert & Detection Engineering*
