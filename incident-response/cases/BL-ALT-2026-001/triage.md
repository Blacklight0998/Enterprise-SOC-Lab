## SOC Alert Triage Report

> Standardized template for the initial triage, investigation, classification, and escalation of security alerts.

---

## 1. Case Information

| Field | Value |
|---|---|
| **Alert ID** | BL-ALT-2026-001 |
| **Alert Name** | Multiple Failed Logon Attempts (incorrect PIN, local interactive) |
| **Origin** | Lab-generated: self-initiated test, not a production alert |
| **Analyst** | Andy Vega |
| **Date Opened** | 2026-10-23 |
| **Detection Time** | 2026-10-23 15:53:06 CST (UTC-6) |
| **Detection Source** | Windows Security Event Log (manual review with PowerShell) |
| **Severity** | Informational |
| **Priority** | P4 |
| **Status** | Closed |

---

## 2. Alert Summary

### Description

Four Windows Security Event ID 4625 (failed logon) events were recorded within about 5 seconds (15:53:06 to 15:53:11) on the lab workstation. All four are logon type 2 (interactive), show sub status `0xC0000380` (incorrect PIN) and originate from the loopback address `127.0.0.1`.

About 16 seconds after the last failure (15:53:27), a successful logon and unlock sequence was recorded: Event IDs 4624, 4648 and 4672.

The analyst generated this activity on purpose to practice triage: three incorrect Windows Hello PIN entries were intended between 15:52 and 15:55, followed by a normal sign-in. Four failure events were recorded instead of three (see Section 13).

### Detection Logic

Manual review of the Windows Security log in a 30-minute window around the test (2026-10-23 15:40 to 16:10), first for failures and then for the logon activity around them.

```text
# Query 1: failed logons (4625)
$a=Get-Date '2026-10-23 15:40'; $b=Get-Date '2026-10-23 16:10'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$a; EndTime=$b} |
  ForEach-Object { $d=@{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' };
    [pscustomobject]@{Hora=$_.TimeCreated; Cuenta=$d.TargetUserName; Tipo=$d.LogonType; Status=$d.Status;
      SubStatus=$d.SubStatus; Proceso=$d.ProcessName; Equipo=$d.WorkstationName; IP=$d.IpAddress} } | Format-Table -AutoSize

# Query 2: successful logons, explicit credentials and special privileges (4624, 4648, 4672)
# Same window; system accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, UMFD-*, DWM-*, machine accounts ending in $) are filtered out.
```

### Initial Context

Repeated failed logons are a common signal of password guessing (brute force). They can also be ordinary typing mistakes at a lock screen. The goal of the triage is to decide which of the two the evidence supports, and what the logs can and cannot prove.

---

## 3. Affected Entities

| Entity Type | Value | Context |
|---|---|---|
| Hostname | Lab workstation (name omitted) | Single Windows 10/11 system used for the lab |
| Username | Lab user account (Microsoft account, name redacted) | Appears in the 4624, 4648 and 4672 events. The 4625 events show `-` as the account name |
| Source IP | 127.0.0.1 | Loopback. The failures did not come from the network |
| Destination IP | Not applicable | No network connection involved |
| Domain | Not collected | Domain fields were not part of the queries |
| Process | `svchost.exe`, `lsass.exe` | Paths seen in the events: `C:\Windows\System32\` |
| File | Not applicable | |

---

## 4. Initial Evidence

| Timestamp (CST) | Source | Event / Observation |
|---|---|---|
| 2026-10-23 15:53:06 | Windows Security log | 4625, logon type 2, Status `0xC000006D`, SubStatus `0xC0000380`, `svchost.exe`, 127.0.0.1, account `-` |
| 2026-10-23 15:53:08 | Windows Security log | 4625, same values as above |
| 2026-10-23 15:53:10 | Windows Security log | 4625, same values as above |
| 2026-10-23 15:53:11 | Windows Security log | 4625, same values as above |
| 2026-10-23 15:53:27 | Windows Security log | 4624 type 7 (unlock) x2 via `lsass.exe`, 4648 via `lsass.exe`, 4672 x2 |
| 2026-10-23 15:53:27 | Windows Security log | 4624 type 11 (cached interactive) x2 via `svchost.exe` from 127.0.0.1, 4648 via `svchost.exe` |

The success events share one-second timestamps, so their exact order inside that second is not reliable.

### Evidence Sources

- [ ] SIEM
- [ ] EDR
- [x] Windows Event Logs
- [ ] Sysmon
- [ ] Firewall
- [ ] IDS/IPS
- [ ] DNS logs
- [x] Authentication logs
- [ ] PCAP
- [ ] Email headers
- [ ] Threat Intelligence
- [ ] Other

---

## 5. Triage Questions

### Is the activity expected?

**Answer:** Yes.

**Evidence:** The analyst performed the test and noted its time window (15:52 to 15:55). The four 4625 events fall inside it, and the query for the whole 15:40 to 16:10 window returned no other failed logons.

---

### Does the activity present a security risk?

**Answer:** No, not in this case.

**Evidence:** The failures are local (logon type 2, loopback source), stopped after four attempts in about 5 seconds, and were followed by a successful unlock. There is no repeated guessing over time and no network origin.

---

### Are additional users, hosts, or systems involved?

**Answer:** No evidence of any.

**Evidence:** After filtering system accounts, the 4624, 4648 and 4672 events in the window belong to a single account, and the only source address is loopback.

Limitation: the 4625 events do not record an account name (`-`), so tying the failures to that account relies on timing, sequence and the analyst's own knowledge of the test, not on the events alone.

---

### Is there evidence of compromise?

**Answer:** No.

**Evidence:** None in the data collected. The investigation used only the Windows Security log. No endpoint telemetry (Sysmon, EDR) or other sources were available in the lab.

---

### Is immediate containment required?

**Answer:** No.

**Reason:** The activity is explained, self-generated and followed by a normal logon. There is nothing to isolate, disable or block.

---

## 6. Indicators & Artifacts

> An observed indicator is not automatically malicious. Record the context and validation status.

| Type | Value | Reputation / Status | Context |
|---|---|---|---|
| IP Address | 127.0.0.1 | Not applicable | Loopback address. It is not routable, so a reputation lookup has no meaning |
| Domain | None | Not applicable | |
| URL | None | Not applicable | |
| SHA256 | Not collected | Not validated | Hashes of the processes were not collected |
| File | None | Not applicable | |
| Process | `svchost.exe`, `lsass.exe` | Path observed under `C:\Windows\System32\`; binary not verified | A path in a log is not proof that the binary is genuine |
| User Account | Lab account (redacted) | Known owner | The analyst's own account |

---

## 7. Threat Intelligence Enrichment

| Indicator | Source | Result | Confidence |
|---|---|---|---|
| 127.0.0.1 | Not queried | Not applicable | Not applicable |

### Notes

No external indicators were observed, so no enrichment was performed.

---

## 8. Analyst Assessment

### Disposition

- [ ] True Positive — Malicious
- [ ] True Positive — Suspicious
- [x] Benign Positive
- [ ] False Positive
- [ ] Inconclusive

### Analyst Confidence

- [ ] Low
- [ ] Medium
- [x] High

### Assessment

The alert fired for a real condition (repeated failed logons), so it is a benign positive and not a false positive. The cause is known because the analyst produced the activity, and the evidence is consistent with it.

**Observed facts:**

- Four 4625 events between 15:53:06 and 15:53:11, logon type 2, Status `0xC000006D`, SubStatus `0xC0000380`, process `svchost.exe`, source `127.0.0.1`, account name `-`.
- `0xC0000380` is `STATUS_SMARTCARD_WRONG_PIN`, which matches an incorrect PIN.
- A successful logon and unlock sequence (4624 types 7 and 11, 4648, 4672) was recorded at 15:53:27 for a single non-system account.
- No other failed logons appear between 15:40 and 16:10.

**Analyst hypothesis:**

- The four events correspond to the analyst's incorrect PIN entries. The fourth event may be an extra attempt or a retry by the sign-in process; this was not resolved.
- Two 4624 events per logon type may be the paired sessions Windows creates for an administrator account. This was not verified.

**Conclusion:**

- Benign Positive: self-generated local PIN failures followed by a successful unlock. No evidence of malicious activity.
- The logs alone cannot tell the owner's mistyped PIN apart from someone with physical access to the keyboard. In a real case, the user would have to confirm.

---

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Supporting Evidence |
|---|---|---|---|
| None | None mapped | Not applicable | No malicious behavior was identified |

> Map ATT&CK techniques only when the observed behavior provides sufficient evidence.

Brute Force (T1110) was considered because the pattern resembles it, but it is not supported: four failures in about 5 seconds, one local interactive session, loopback origin and a normal unlock right after.

---

## 10. Scope Assessment

### Confirmed Affected Assets

- Lab workstation (single system, no impact)

### Potentially Affected Assets

- None identified

### Additional Investigation Required

- None for this alert

---

## 11. Recommended Actions

### Immediate

- [x] No action required
- [ ] Continue monitoring
- [ ] Collect additional logs
- [ ] Isolate endpoint
- [ ] Disable / restrict account
- [ ] Block IP / domain / hash
- [ ] Escalate investigation
- [x] Preserve evidence
- [x] Other

### Action Details

- Evidence preserved in `evidence/` (screenshots and CSV transcriptions, account name redacted).
- Other (not applied yet): the Security log is a circular log of 20 MB (`20,971,520` bytes) with 33,105 records, and its oldest event is from 2026-10-17 10:16:39. That is roughly 6 days of history at the current event volume, so older events are overwritten. Recommend increasing the maximum size and, once the lab has a SIEM, forwarding Windows logs to it.

---

## 12. Escalation Decision

| Field | Value |
|---|---|
| **Escalation Required** | No |
| **Escalation Level** | Not applicable |
| **Escalation Time** | Not applicable |
| **Reason** | Benign Positive: known, self-generated activity with no evidence of compromise |

### Information Provided to Escalation Team

Not applicable.

---

## 13. Analyst Notes

```text
Analyst notes:

- How the event was generated: lock the session (Win+L), enter three incorrect Windows Hello PIN
  attempts, then sign in normally. Windows 10/11 with a Microsoft account.
- Count mismatch: three attempts were intended and four 4625 events were recorded.
  I did not find the reason.
- The 4625 events show "-" as the account name. A detection rule that depends on the target
  account name would miss these failures or could not attribute them. Microsoft documents similar
  behavior for incorrect smart card PIN entries (KB 2157973); here it was observed with a
  Windows Hello PIN.
- The source address of a local interactive failure is the loopback address. An IP-based rule or
  IP reputation check would add nothing here. Logon type, sub status and process are more useful.
- Only the Security log was reviewed. A SIEM, Sysmon or EDR would add context.
- Log retention: oldest event 2026-10-17 10:16:39, so earlier activity is no longer available.
  This was a lab-generated case because older events had already been overwritten.
- Console output was transcribed to CSV by hand. Account names are redacted in screenshots and CSV.
```

---

## 14. Closure

| Field | Value |
|---|---|
| **Final Status** | Closed |
| **Final Disposition** | Benign Positive (lab-generated) |
| **Closure Time** | 2026-10-23 |
| **Resolution** | No action required. Log retention recommendation recorded |

### Closure Summary

Four failed interactive logons with an incorrect PIN were recorded within 5 seconds from the loopback address, followed by a normal unlock. The activity was produced by the analyst as a test, and nothing in the evidence suggests compromise. The alert was closed as a Benign Positive. The case also showed three detection limits: the account name is missing from the failure events, the source IP is not informative for local logons, and the Security log keeps only about six days of history.

---

## 15. Evidence References

| Evidence ID | Description | Location |
|---|---|---|
| EV-001 | Security log mode, maximum size and record count | `evidence/EV-001_security_log_size.png` |
| EV-002 | Oldest event in the Security log (2026-10-17 10:16:39) | `evidence/EV-002_oldest_event.png` |
| EV-003 | Query 1 result: four 4625 events | `evidence/EV-003_4625_events.png`, `evidence/EV-003_4625_events.csv` |
| EV-004 | Query 2 result: 4624, 4648 and 4672 events at 15:53:27 | `evidence/EV-004_logon_context.png`, `evidence/EV-004_logon_context.csv` |

---

# Document Control

| Field | Value |
|---|---|
| **Framework** | Blacklight Incident Response Framework |
| **Template** | SOC Alert Triage |
| **Version** | 1.0 |
| **Environment** | Cybersecurity Training / Portfolio Lab |
| **Classification** | Public |
