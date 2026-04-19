"""
Detection thresholds and configuration.
Values are intentionally conservative — tune to your environment.
"""

from pathlib import Path

# --- Paths ---
DATA_DIR = Path("data")
OUTPUT_DIR = Path("output")
TI_CACHE_FILE = DATA_DIR / "blacklist_cache.json"

# --- Detection thresholds ---
# Number of 401 responses from one IP before it's flagged as brute force
FAILED_LOGIN_THRESHOLD = 5

# Requests per IP per log file that trigger a high-traffic alert
HIGH_REQUEST_THRESHOLD = 200

# If a time bucket has SPIKE_MULTIPLIER times more requests than average → spike alert
SPIKE_MULTIPLIER = 3

# Minimum requests for a blacklisted IP to generate an alert (avoids noise from scanners)
TI_MIN_REQUESTS = 3

# --- Threat Intelligence ---
# Leave empty to skip API fetch and rely on cache or local blacklist only
TI_API_KEY = ""
TI_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"

# --- Severity mapping per detection type ---
SEVERITY = {
    "BRUTEFORCE":    "HIGH",
    "BLACKLIST_HIT": "HIGH",
    "TRAFFIC_SPIKE": "MEDIUM",
    "HIGH_TRAFFIC":  "MEDIUM",
}
