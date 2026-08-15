from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

DATA_DIR = Path("data")
TI_CACHE  = DATA_DIR / "blacklist_cache.json"

FAILED_LOGIN_THRESHOLD  = 5
FAILED_LOGIN_WINDOW_MINUTES = 5
HIGH_REQUEST_THRESHOLD  = 200
SPIKE_MULTIPLIER        = 3
TI_MIN_REQUESTS         = 3

TI_API_KEY = os.getenv("TI_API_KEY") # put your api key in .env
TI_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"

SEVERITY = {
    "BRUTEFORCE":    "HIGH",
    "BLACKLIST_HIT": "HIGH",
    "TRAFFIC_SPIKE": "MEDIUM",
    "HIGH_TRAFFIC":  "MEDIUM",
}
