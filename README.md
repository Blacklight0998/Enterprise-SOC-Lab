# Enterprise SOC Detection & Incident Response Lab

This is my long-term homelab for practicing security monitoring, detection engineering and incident investigation in a more realistic environment than isolated class exercises.

The lab is still in progress. I expand it gradually and only document capabilities after I have implemented and tested them.

## Goal

The goal is to maintain one environment that can grow with my SOC / Blue Team skills instead of creating a disconnected lab for every topic.

Current and future work is centered on:

- Windows security monitoring;
- log collection and analysis;
- Microsoft Sentinel and KQL;
- detection engineering;
- alert and incident triage;
- Linux monitoring;
- Windows / Active Directory practice as the environment expands.

## Current status

**Active build / in progress.** Three triage cases are documented. The lab now covers local authentication triage, end-to-end RDP brute-force detection, and Windows process-behavior detection with containment and AppLocker mitigation.

### Current Sentinel pipeline

```text
Windows Server VM
        ↓
Windows Security Events
        ↓
Azure Monitor Agent + Data Collection Rule
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel
        ↓
KQL / Analytics Rule
        ↓
Alert + Incident
        ↓
SOC triage and closure
```

## Cases

| Case | Summary | Disposition |
|---|---|---|
| [BL-ALT-2026-001](./incident-response/cases/BL-ALT-2026-001/triage.md) | Four failed interactive logons (incorrect Windows Hello PIN), generated as a lab test and followed by a normal unlock | Benign Positive (lab-generated) |
| [BL-ALT-2026-002](./incident-response/cases/BL-ALT-2026-002/triage.md) | Simulated RDP brute-force activity against the Azure lab, detected end-to-end with a custom Microsoft Sentinel Analytics Rule | True Positive — detection validation (lab-generated) |
| [BL-ALT-2026-003](./incident-response/cases/BL-ALT-2026-003/triage.md) | Controlled repeated `cmd.exe` process creation detected through Event ID 4688 and Microsoft Sentinel, followed by process investigation, containment, AppLocker mitigation and post-mitigation validation | Benign Positive — authorized security testing |

Cases use the [SOC alert triage template](./incident-response/templates/SOC-INCIDENT-TRIAGE-TEMPLATE.md).

## Current environment and tools

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics Workspace
- Azure Monitor Agent
- Data Collection Rules
- Windows Server
- Windows Security Event logs
- KQL
- AppLocker
- Kali Linux for authorized lab activity generation
- Oracle VirtualBox for local lab work

## Why I keep this separate

Most of my other portfolio work started from focused university exercises. This repository is different: it is an ongoing environment that I can keep expanding as my SOC and Blue Team skills develop.
