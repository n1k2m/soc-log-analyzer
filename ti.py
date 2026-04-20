import json
import logging
from pathlib import Path

import requests

from config import TI_API_KEY, TI_API_URL, TI_CACHE

log = logging.getLogger(__name__)


def load_ti_data():
    if Path(TI_CACHE).exists():
        try:
            with open(TI_CACHE) as f:
                data = json.load(f)
            log.info(f"ti cache: {len(data)} entries")
            return data
        except (json.JSONDecodeError, OSError):
            log.warning("ti cache corrupted, trying api")

    if not TI_API_KEY:
        log.warning("no TI_API_KEY, skipping blacklist checks")
        return {}

    try:
        r = requests.get(
            TI_API_URL,
            headers={"Key": TI_API_KEY, "Accept": "application/json"},
            params={"confidenceMinimum": 90},
            timeout=15,
        )
        r.raise_for_status()
        data = {x["ipAddress"]: x for x in r.json().get("data", [])}

        with open(TI_CACHE, "w") as f:
            json.dump(data, f)
        log.info(f"fetched {len(data)} IPs from abuseipdb")
        return data

    except requests.RequestException as e:
        log.warning(f"ti fetch failed: {e}")
        return {}
