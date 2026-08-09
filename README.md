# SentinelScan — PS-4: Unified Cross-Platform Malware Detection & Behavioral Analysis Suite

**E-Rakshak 2026 · Round 2 · Team HackersAPK** — Rank 6 Qualifier
Problem Statement: **ERH26_PS_04** — Cybersecurity & Malware Analysis

A localized, evidence-grade platform for police cyber-crime units to statically and dynamically analyze suspicious Android APKs and Windows executables — identifying what data is stolen, where it's sent, and producing a plain-language report an investigator (not just an analyst) can act on.

---

## Table of Contents

- [Problem Understanding](#problem-understanding)
- [What Makes This Different](#what-makes-this-different)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Team & Ownership](#team--ownership)
- [Roadmap](#roadmap)
- [Deployment](#deployment)
- [Contributing Workflow](#contributing-workflow)

---

## Problem Understanding

Police departments encounter endpoints compromised by spyware, RATs, and malicious APKs — light-bill fraud, loan-app scams, fake e-Challan/RTO schemes. Investigators need a safe, isolated environment to scan a suspect/victim device, determine exactly what capability the malware has (SMS theft, GPS tracking, screen capture) and where it exfiltrates to, across **both Windows and Android**, with a report that holds up as evidence and is readable by a non-technical officer.

**Core pipeline (per the PS):**

1. **Static Analysis** — hashing, YARA/signature matching, APK manifest & permission scan, PE inspection, string/URL/IP extraction
2. **Dynamic / Sandbox Analysis** — isolated detonation, API/syscall + network traffic capture, file/registry/SMS access tracking
3. **Behavioral Profiling** — capability classification, MITRE ATT&CK mapping, plain-language summary
4. **Reporting & IOCs** — exportable CSV/STIX, hash-chained evidence-grade logging

**Bonus objectives targeted:** automated MITRE ATT&CK mapping, encrypted-traffic behavioral analysis (metadata-only, no decryption), threat-intel enrichment, offline/air-gapped mode.

---

## What Makes This Different

4-5 teams are building against the same PS. Our locked differentiators:

| #   | Feature                                                          | Why it matters                                                                                                                                                               |
| --- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **India-specific scam detection rules**                          | YARA/behavioral signatures tuned to light-bill, loan-app, and e-Challan fraud patterns explicitly named in the PS — most teams build generic malware detection and miss this |
| 2   | **LangGraph agent correlation + plain-language narrative agent** | Turns raw static+dynamic+network signals into an investigator-readable summary instead of a raw log dump                                                                     |
| 3   | **Hash-chained, signed chain-of-custody reporting**              | Evidence-grade, court-ready reports — its own visible dashboard module, not a buried backend feature                                                                         |

**Stretch (Week 4, if time allows):** 24/7 live GCP-hosted sandbox, encrypted-traffic metadata analysis (JA3 fingerprinting), Geo-IP mapping, AI-generated investigative recommendations, malware family tagging.

---

## Architecture

Six-layer pipeline — full diagram at [`infra/PS4_Architecture.drawio`](./infra/PS4_Architecture.drawio) (open in [diagrams.net](https://app.diagrams.net)):

```
Ingestion & Isolation Layer
        ↓
Static Analysis Engine        (APK/PE modules, YARA, ML classifier)
        ↓
Dynamic / Sandbox Analysis    (KVM + CAPE on GCP, Android-x86 + Frida, INetSim)
        ↓
Behavioral Correlation & Agentic Reasoning   ← differentiator layer
   (LangGraph Orchestrator → MITRE Mapper → Capability Classifier → Narrative Agent)
        ↓
Storage & Serving             (PostgreSQL, Elasticsearch, Redis)
        ↓
Output                        (React Dashboard, IOC Export, Signed PDF Report)
```

**Deployment model:** two-plane architecture — a public Control Plane (dashboard/API, port 443 only) and an isolated Detonation Plane (GCP `n2-standard-4`, nested virtualization, KVM/CAPE, network-contained via INetSim). See [Deployment](#deployment) below.

---

## Tech Stack

### Backend / Agents

| Component           | Choice                                                        |
| ------------------- | ------------------------------------------------------------- |
| Agent orchestration | LangGraph                                                     |
| LLM routing         | Groq (routine) + Kimi K2.6 via NVIDIA NIM (complex/narrative) |
| API                 | FastAPI                                                       |
| Auth                | JWT (custom, hand-coded — no third-party auth provider)       |
| Databases           | PostgreSQL, Elasticsearch, Redis                              |

### Dynamic Sandbox

| Component           | Choice                                                              |
| ------------------- | ------------------------------------------------------------------- |
| Host                | Google Cloud Compute Engine, `n2-standard-4`, nested virtualization |
| Hypervisor          | KVM/QEMU                                                            |
| Sandbox engine      | CAPE (Windows detonation, auto-revert golden snapshot)              |
| Android sandbox     | Android-x86 (QEMU) + Frida instrumentation                          |
| Network containment | INetSim sinkhole                                                    |

### Frontend

Hand-coded, no AI page-builders — full control over report UX.

| Package                      | Version |
| ---------------------------- | ------- |
| react / react-dom            | 19.2.7  |
| typescript                   | 7.0.2   |
| vite                         | 8.1.4   |
| react-router-dom             | 7.18.1  |
| tailwindcss                  | 4.3.2   |
| zustand                      | 5.0.14  |
| @tanstack/react-query        | 5.101.2 |
| gsap / @gsap/react           | 3.15.0  |
| @xyflow/react                | 12.11.2 |
| shadcn/ui (Radix primitives) | latest  |

**GSAP plugins used:** ScrambleText (hero decrypt effect), ScrollTrigger (scroll reveals), DrawSVG (IOC graph line-draw), SplitText (line-by-line report reveal), useGSAP (React lifecycle hook).

---

## Repository Structure

```
ps4-malware-suite/
├── ingestion/                  # Ingestion gateway, isolation controller
├── static-analysis/            # APK/PE static modules, YARA, ML classifier
│   └── yara_rules/india_scam_rules/    # differentiator #1
├── dynamic-sandbox/             # CAPE config, Android-x86, network capture
├── agents/                     # differentiator #2
│   ├── orchestrator/           # LangGraph orchestrator (schema.py, orchestrator.py)
│   ├── mitre_mapper/
│   ├── capability_classifier/
│   └── narrative_agent/
├── storage/                    # DB schemas (postgres, elasticsearch)
├── backend/app/                 # FastAPI app
├── frontend/src/                # React dashboard, login, landing page
├── docs/                       # weekly documentation (updated every week)
└── infra/                      # GCP setup scripts, architecture diagram
```

---

## Getting Started

### Backend / infra

```bash
cp .env.example .env      # fill in GROQ_API_KEY, NVIDIA_NIM_API_KEY, GCP project details
docker-compose up -d      # Postgres + Redis + Elasticsearch
```

### Agent orchestrator (standalone test)

```bash
pip install -r agents/orchestrator/requirements.txt
python agents/orchestrator/orchestrator.py
```

Runs the LangGraph pipeline against mock static-analysis data — confirms the graph end-to-end without needing the live sandbox.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## Team & Ownership

| Member              | Owns                                                                                              |
| ------------------- | ------------------------------------------------------------------------------------------------- |
| **Member 1**        | Static analysis & ML — APK/PE static engine, YARA (incl. India scam rules), string/IOC extraction |
| **Member 2**        | Dynamic sandbox & cloud infra — GCP, KVM/CAPE, Android-x86, INetSim, evidence logger              |
| **Neil (Member 3)** | Agent layer — LangGraph orchestrator, MITRE mapper, capability classifier, narrative agent        |
| **Member 4**        | Dashboard, reporting & storage — React frontend, DB schemas, IOC export, chain-of-custody module  |

Weekly sync: every Thursday mentor meeting, each member demos their slice against the same sample.

---

## Roadmap

| Week | Dates               | Focus                                                                                                                                                    |
| ---- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | Wed 08 – Thu 09 Jul | Scope lock, architecture, repo, GCP provisioning, sample sourcing                                                                                        |
| 2    | Fri 10 – Thu 16 Jul | Static analysis engine, ingestion/isolation, GCP+CAPE install, orchestrator skeleton                                                                     |
| 3    | Fri 17 – Thu 23 Jul | Dynamic sandbox live (Android + Windows), network capture, orchestrator wired to real data                                                               |
| 4    | Fri 24 – Thu 30 Jul | MITRE/capability/narrative agents finalized, dashboard (incl. Process Tree, Risk Score, Evidence Timeline), PPT + demo video, final submission on Unstop |

Full plan with daily/task-level detail
: see `docs/` and the project plan PDF.

---

## Deployment

**Control Plane** (public): Dashboard, API, DB — reverse-proxied via Nginx + Let's Encrypt, port 443 only.

**Detonation Plane** (isolated): GCP `n2-standard-4`, Ubuntu 22.04, nested virtualization enabled at creation. KVM/QEMU + CAPE for Windows detonation with auto-reverting golden snapshot; Android-x86 QEMU VM with Frida. All victim-VM traffic routed through INetSim — no real internet access, so captured C2/exfil behavior is observed safely. SSH-only management access; only the Control Plane is internet-facing.

Cost: $0 for the full hackathon timeline — new GCP account's $300/90-day trial credit covers it.

---

## Contributing Workflow

```bash
git checkout -b feature/<short-description>
# ...make changes...
git add .
git commit -m "clear, specific message"
git push -u origin feature/<short-description>
# open a PR into main
```

- Never commit real malware samples — `dynamic-sandbox/samples/` and `*.apk`/`*.exe` are gitignored
- Never commit `.env` — use `.env.example` as the template
- Keep `docs/weekX.md` updated every week, not just at submission time

---

**Submission:** Final prototype, documentation, PPT, and demo video submitted via Unstop at end of Week 4.
