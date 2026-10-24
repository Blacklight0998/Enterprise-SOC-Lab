# Enterprise SOC Lab

This is my long-term homelab for practicing cybersecurity in a more realistic environment than isolated class exercises.

The project is still in progress. I am building it gradually while I learn more about networking, Windows, Linux, monitoring and incident investigation.

## Goal

The idea is to have one lab that I can keep expanding instead of creating a new environment for every topic.

Over time I want to use it for things such as:

- Windows and Linux administration
- network troubleshooting
- security monitoring
- log collection
- incident investigation
- Active Directory practice
- SIEM labs
- Blue Team exercises

## Current status

Early build / in progress. Two triage cases completed so far; an Azure Sentinel SIEM pipeline is deployed and used for case 002.

At this stage I am using the repository to document the environment and the work I complete as it becomes real. I do not want to list planned tools or features as if they were already deployed.

## Cases

| Case | Summary | Disposition |
|---|---|---|
| [BL-ALT-2026-001](./incident-response/cases/BL-ALT-2026-001/triage.md) | Four failed interactive logons (incorrect Windows Hello PIN), generated as a lab test and followed by a normal unlock | Benign Positive (lab-generated) |
| [BL-ALT-2026-002](./incident-response/cases/BL-ALT-2026-002/triage.md) | Simulated RDP brute-force (8 failed logons, non-existent account) against the Azure Sentinel lab, detected end-to-end by a custom Analytics Rule | True Positive — detection validation (lab-generated) |

Cases use the [SOC alert triage template](./incident-response/templates/SOC-INCIDENT-TRIAGE-TEMPLATE.md).

## Environment

Current tools/platforms I am using or preparing around this lab:

- Oracle VirtualBox
- Windows
- Linux

More documentation will be added as I build and test each part of the environment.

## Why I keep this separate

Most of my other portfolio work started from focused university exercises. This repository is different: the goal is to keep one environment alive and improve it over time as my SOC and Blue Team skills grow.
