from pathlib import Path

DATA_DIR = Path("data")
TI_CACHE  = DATA_DIR / "blacklist_cache.json"

# tweak these per environment
FAILED_LOGIN_THRESHOLD  = 5
HIGH_REQUEST_THRESHOLD  = 200
SPIKE_MULTIPLIER        = 3
TI_MIN_REQUESTS         = 3

TI_API_KEY = ""  # set via env or .env, don't commit
TI_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"

SEVERITY = {
    "BRUTEFORCE":    "HIGH",
    "BLACKLIST_HIT": "HIGH",
    "TRAFFIC_SPIKE": "MEDIUM",
    "HIGH_TRAFFIC":  "MEDIUM",
}