# Project Context — ForensicAI-Engine

## What this is
AI-powered incident triage pipeline for two scopes:
- Scope 1: Bare metal Ubuntu VM (192.168.1.10)
- Scope 2: Windows 10 VM (192.168.1.6)

## Host machine
MacBook Air M2 (arm64) - 192.168.1.3
Runs: Velociraptor server, MISP (Docker), YARA rules

## Tools per scope
Scope 1: Velociraptor agent, osquery, AIDE, LiME, Plaso, YARA, MISP
Scope 2: Velociraptor agent, Sysmon, KAPE, EvtxECmd, YARA, MISP

## Key paths
- Project: /Users/srinithi/ForensicAI-Engine/
- Velociraptor binary: /Users/srinithi/Downloads/tools/velociraptor
- Velociraptor config: /Users/srinithi/velociraptor-server/server.config.yaml
- MISP: https://localhost (Docker)
- YARA rules: /Users/srinithi/yara-rules
- Atomic Red Team Linux: /home/admin/atomic-red-team/atomics
- Atomic Red Team Windows: C:\AtomicRedTeam\atomics

## IPs
- Mac host: 192.168.1.3
- Ubuntu VM: 192.168.1.10, user: admin
- Windows VM: 192.168.1.6, user: admin

## Pipeline flow
Attack simulation → Acquisition layer → OCSF normalisation → Feature extraction → AI triage

## Directory structure
ForensicAI-Engine/
├── orchestrator/       # main.py
├── acquisition/        # bare_metal_acquirer.py, vmware_acquirer.py
├── parsing/
│   └── ocsf_mappers/  # one mapper per tool output
├── normalisation/      # feature_extractor.py
├── ai_triage/         # model training and inference
├── config/            # .env file with credentials
├── data/
│   ├── raw/           # raw tool outputs per incident
│   ├── processed/     # OCSF mapped events
│   └── labeled/       # feature vectors with labels
├── logs/
└── tests/

## Current status
All tools installed and verified. Ready to write Python files.

## Start here
Always read CONTEXT.md first before writing any code.
