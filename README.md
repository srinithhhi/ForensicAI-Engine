# ForensicAI-Engine

An AI-powered digital-forensics and incident-triage pipeline that automates evidence collection, normalisation, and machine-learning-based triage across Linux and Windows hosts.

## Overview
ForensicAI-Engine ingests host telemetry and forensic artifacts, normalises them into a common schema (OCSF), extracts features, and applies a machine-learning model to prioritise security incidents by risk — reducing manual effort in Security Operations Centers.

## Pipeline
Attack simulation → Evidence acquisition → OCSF normalisation → Feature extraction → AI triage

## Key capabilities
- Automated evidence acquisition from Linux and Windows endpoints
- Threat detection with YARA and threat-intelligence enrichment via MISP
- Attack simulation with Atomic Red Team to generate labelled training data
- Normalisation of heterogeneous tool outputs into the OCSF schema
- Machine-learning triage that scores and ranks incidents by risk

## Tooling
- **Collection / EDR:** Velociraptor, osquery, Sysmon, KAPE, LiME, Plaso
- **Detection / intelligence:** YARA, MISP
- **Simulation:** Atomic Red Team
- **ML / API:** scikit-learn, FastAPI

## Repository structure
- `acquisition/` — endpoint evidence acquirers
- `parsing/` — OCSF mappers (one per tool output)
- `normalisation/` — feature extraction
- `ai_triage/` — model training and inference
- `simulation/` — attack simulation harness
- `schemas/` — OCSF / data schemas
- `ui/` — dashboard
- `tests/` — test suite

## Tech stack
Python · scikit-learn · FastAPI · Velociraptor · YARA · MISP · OCSF

## Status
Active development.