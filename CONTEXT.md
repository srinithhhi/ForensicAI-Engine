# Project Context — ForensicAI-Engine

## What this is
An AI-powered incident-triage pipeline that acquires, normalises and triages forensic
evidence across two target scopes:
- **Scope 1:** Ubuntu Linux VM
- **Scope 2:** Windows 10 VM

## Environment
- **Host:** macOS (Apple Silicon) — runs the Velociraptor server, MISP (Docker) and YARA rules
- **Targets:** Linux and Windows virtual machines, each running a Velociraptor agent
- Network addresses, hostnames and credentials are kept in a local, untracked `config/.env`
  file and are intentionally not committed to this repository.

## Tools per scope
- **Scope 1 (Linux):** Velociraptor agent, osquery, AIDE, LiME, Plaso, YARA, MISP
- **Scope 2 (Windows):** Velociraptor agent, Sysmon, KAPE, EvtxECmd, YARA, MISP
- **Attack simulation:** Atomic Red Team (Linux and Windows atomics)

## Pipeline flow
Attack simulation → Acquisition layer → OCSF normalisation → Feature extraction → AI triage

## Directory structure
```
ForensicAI-Engine/
├── orchestrator/       # main.py
├── acquisition/        # bare_metal_acquirer.py, vmware_acquirer.py
├── parsing/
│   └── ocsf_mappers/   # one mapper per tool output
├── normalisation/      # feature_extractor.py
├── ai_triage/          # model training and inference
├── config/             # local .env (untracked) with credentials and host details
├── data/
│   ├── raw/            # raw tool outputs per incident
│   ├── processed/      # OCSF-mapped events
│   └── labeled/        # feature vectors with labels
├── logs/
└── tests/
```

## Configuration
All host addresses, VM details, tool paths and credentials are environment-specific and
must be supplied via a local `config/.env` file (not committed). See `requirements.txt`
for Python dependencies.

## Status
Active development.