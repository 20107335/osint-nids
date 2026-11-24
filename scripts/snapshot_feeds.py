"""
Daily threat-feed snapshot.

Downloads the current malicious-IOC feeds and saves them, untouched, into
data/raw/feeds/<YYYY-MM-DD>/ so we build a dated history (needed for the
time-based train/test split). Feeds roll old entries off, so anything not
saved on the day is lost - run this once a day via Task Scheduler / cron.

Usage (from the repo root, venv active):
    python scripts/snapshot_feeds.py
"""
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# Make src/ importable when running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from osint_nids.config import ABUSECH_AUTH_KEY, DATA_RAW  # noqa: E402

FEEDS_DIR = DATA_RAW / "feeds"
LOG_FILE = FEEDS_DIR / "snapshot_log.csv"
TIMEOUT = 60
HEADERS = {"User-Agent": "osint-nids-fyp/0.1 (student research project)"}


def fetch_feodo():
    """Feodo Tracker botnet C2 IP blocklist (malicious IPs)."""
    r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                     headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    return "feodo_ipblocklist.csv", r.content


def fetch_urlhaus():
    """URLhaus recent malware URLs (needs abuse.ch Auth-Key)."""
    if not ABUSECH_AUTH_KEY:
        raise RuntimeError("ABUSECH_AUTH_KEY missing from .env")
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{ABUSECH_AUTH_KEY}/recent.csv"
    r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    return "urlhaus_recent.csv", r.content


def fetch_threatfox():
    """ThreatFox IOCs first seen in the last day (IPs, domains, URLs, hashes)."""
    if not ABUSECH_AUTH_KEY:
        raise RuntimeError("ABUSECH_AUTH_KEY missing from .env")
    r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                      headers={**HEADERS, "Auth-Key": ABUSECH_AUTH_KEY},
                      json={"query": "get_iocs", "days": 1}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") not in ("ok", "no_result"):
        raise RuntimeError(f"ThreatFox query_status: {data.get('query_status')}")
    return "threatfox_1day.json", json.dumps(data, indent=1).encode()


def fetch_openphish():
    """OpenPhish community phishing URL feed."""
    r = requests.get("https://openphish.com/feed.txt", headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    return "openphish_feed.txt", r.content


FEEDS = {
    "feodo": fetch_feodo,
    "urlhaus": fetch_urlhaus,
    "threatfox": fetch_threatfox,
    "openphish": fetch_openphish,
}


def log(row):
    new = not LOG_FILE.exists()
    with LOG_FILE.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp_utc", "feed", "status", "file", "bytes", "error"])
        if new:
            w.writeheader()
        w.writerow(row)


def main():
    now = datetime.now(timezone.utc)
    day_dir = FEEDS_DIR / now.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    for name, fetch in FEEDS.items():
        row = {"timestamp_utc": now.isoformat(timespec="seconds"), "feed": name,
               "status": "ok", "file": "", "bytes": 0, "error": ""}
        try:
            filename, content = fetch()
            path = day_dir / filename
            path.write_bytes(content)
            row.update(file=str(path.relative_to(DATA_RAW)), bytes=len(content))
            print(f"[ok]   {name:<10} {len(content):>10,} bytes -> {path}")
        except Exception as e:  # keep going so one broken feed doesn't stop the rest
            failures += 1
            row.update(status="failed", error=str(e)[:300])
            print(f"[FAIL] {name:<10} {e}")
        log(row)

    print(f"\nDone: {len(FEEDS) - failures}/{len(FEEDS)} feeds saved to {day_dir}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()