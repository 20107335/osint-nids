# OSINT-Enriched Network Intrusion Detection System

Final Year Project 2026/27 - Eimhin O'Neill (SETU)

A network intrusion detection system that passively monitors traffic, extracts
indicators of compromise (IPs, domains, anomalous ports/protocols), matches them
against a local blocklist, and enriches unknown IOCs via OSINT sources
(VirusTotal, AbuseIPDB, Shodan). An explainable, calibrated classifier scores
each IOC and a decision engine routes it to auto-block, auto-allow or manual review.

## Repository layout

| Path | Purpose |
|---|---|
| `data/raw/` | Untouched downloads: Kaggle datasets, daily feed snapshots, PCAPs (git-ignored) |
| `data/interim/` | Cleaned / merged data (git-ignored) |
| `data/processed/` | Final feature tables for training (git-ignored) |
| `notebooks/` | Exploration and model development (01_data_collection ... 07_explainability) |
| `src/osint_nids/` | Reusable code shared by notebooks and the live pipeline |
| `scripts/` | Scheduled / CLI jobs (e.g. daily feed snapshot) |
| `sql/` | Postgres schema and migrations |
| `models/` | Saved trained models (git-ignored) |
| `tests/` | Unit tests |

## Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then add your API keys
```

## Datasets

- CIC-IDS Collection (CIC-IDS2017/2018, DoS2017, DDoS2019) - traffic model
- UNSW-NB15 - traffic model, cross-dataset evaluation
- Malicious URLs dataset (Kaggle) - IOC classifier seed data
- Daily snapshots of abuse.ch (Feodo Tracker, ThreatFox, URLhaus) and OpenPhish
- Tranco top sites list - benign domains

## Safety

Malware PCAPs are only opened inside an isolated VM.
