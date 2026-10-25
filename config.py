import ipaddress
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
INSTANCE_DIR = BASE_DIR / "instance"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

DB_PATH = Path(os.environ.get("PHISHGUARD_DB_PATH", INSTANCE_DIR / "analysis_history.db"))
MODEL_PATH = Path(os.environ.get("PHISHGUARD_MODEL_PATH", MODELS_DIR / "phishguard_model.joblib"))
FEATURE_SCHEMA_PATH = Path(os.environ.get("PHISHGUARD_SCHEMA_PATH", MODELS_DIR / "feature_schema.joblib"))
METRICS_PATH = Path(os.environ.get("PHISHGUARD_METRICS_PATH", MODELS_DIR / "evaluation_metrics.json"))
SYNTHETIC_DATASET_PATH = DATA_DIR / "synthetic_urls.csv"
DEFAULT_DATASET_PATH = DATA_DIR / "phishing_urls.csv"

HOST = os.environ.get("PHISHGUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("PHISHGUARD_PORT", "5000"))
DEBUG = False
_configured_secret = os.environ.get("PHISHGUARD_SECRET_KEY", "").strip()
try:
    _loopback_host = ipaddress.ip_address(HOST).is_loopback
except ValueError:
    _loopback_host = HOST.lower() == "localhost"
if not _loopback_host and (
    len(_configured_secret) < 32 or _configured_secret.lower().startswith("replace-with")
):
    raise RuntimeError("Set a unique PHISHGUARD_SECRET_KEY of at least 32 characters beyond localhost.")
SECRET_KEY = _configured_secret or secrets.token_urlsafe(48)
_cookie_secure_setting = os.environ.get("PHISHGUARD_COOKIE_SECURE")
SESSION_COOKIE_SECURE = (
    _cookie_secure_setting.strip().lower() in {"1", "true", "yes"}
    if _cookie_secure_setting is not None
    else not _loopback_host
)
if not _loopback_host and not SESSION_COOKIE_SECURE:
    raise RuntimeError("Set PHISHGUARD_COOKIE_SECURE=1 when binding beyond localhost; use HTTPS.")
HISTORY_RETENTION_DAYS = max(1, int(os.environ.get("PHISHGUARD_HISTORY_RETENTION_DAYS", "90")))
MAX_CONTENT_LENGTH = 4096
EXTERNAL_REQUESTS_PER_MINUTE = max(1, int(os.environ.get("PHISHGUARD_RATE_LIMIT_PER_MINUTE", "30")))
