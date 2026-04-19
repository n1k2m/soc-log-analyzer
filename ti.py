"""
Threat Intelligence loader.

Priority order:
  1. Cache file (data/blacklist_cache.json) — always checked first
  2. AbuseIPDB API — only if TI_API_KEY is set and cache is missing
  3. Empty dict — silent fallback, detections still run without TI

This avoids unnecessary API calls during development and CI runs.
"""

import json
import logging
from pathlib import Path

import requests

from config import TI_API_KEY, TI_API_URL, TI_CACHE_FILE

log = logging.getLogger(__name__)


def _fetch_from_abuseipdb() -> dict:
    """
    Download the current blacklist from AbuseIPDB.
    Returns a dict keyed by IP address.
    Raises requests.RequestException on network/API failure.
    """
    headers = {
        "Key": TI_API_KEY,
        "Accept": "application/json",
    }
    params = {"confidenceMinimum": 90}

    log.info("Fetching TI data from AbuseIPDB...")
    response = requests.get(TI_API_URL, headers=headers, params=params, timeout=15)
    response.raise_for_status()

    payload = response.json()
    return {item["ipAddress"]: item for item in payload.get("data", [])}


def _save_cache(data: dict) -> None:
    TI_CACHE_FILE.parent.mkdir(exist_ok=True)
    with open(TI_CACHE_FILE, "w") as f:
        json.dump(data, f, indent=2)
    log.info(f"TI cache saved to {TI_CACHE_FILE} ({len(data)} entries)")


def load_ti_data() -> dict:
    """
    Load TI data. Returns a dict: { "ip_address": {...metadata...} }
    Returns empty dict on any failure so the rest of the pipeline keeps running.
    """
    # 1. Try local cache first
    if Path(TI_CACHE_FILE).exists():
        try:
            with open(TI_CACHE_FILE) as f:
                data = json.load(f)
            log.info(f"Loaded TI cache from {TI_CACHE_FILE} ({len(data)} entries)")
            return data
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"TI cache is corrupted or unreadable: {e}. Will re-fetch.")

    # 2. Try API if key is configured
    if TI_API_KEY:
        try:
            data = _fetch_from_abuseipdb()
            _save_cache(data)
            return data
        except requests.RequestException as e:
            log.warning(f"TI API request failed: {e}. Continuing without TI data.")

    # 3. Fallback
    log.warning("No TI data available. BLACKLIST_HIT detections will be skipped.")
    return {}
