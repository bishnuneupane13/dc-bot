import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_env(key, default=None):
    """Get stripped environment variable or default"""
    val = os.getenv(key, default)
    if isinstance(val, str):
        return val.strip()
    return val

# Discord Bot Token (REQUIRED)
BOT_TOKEN = get_env("BOT_TOKEN")

# Bot Settings
COMMAND_PREFIX = get_env("COMMAND_PREFIX", "!")
BOT_STATUS = get_env("BOT_STATUS", "Bug Bounty Tools")

# Scan Settings
MAX_CONCURRENT_REQUESTS = int(get_env("MAX_CONCURRENT_REQUESTS", "10"))
REQUEST_TIMEOUT = int(get_env("REQUEST_TIMEOUT", "30"))
RATE_LIMIT = int(get_env("RATE_LIMIT", "5"))

# Logging Settings
DEBUG = get_env("DEBUG", "False").lower() in ("true", "1", "t")
LOG_FILE = get_env("LOG_FILE", "bot.log")

# Result Settings
RESULTS_DIR = get_env("RESULTS_DIR", "results")
MAX_RESULTS_DISPLAY = int(get_env("MAX_RESULTS_DISPLAY", "50"))

# API Keys
SHODAN_API_KEY = get_env("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = get_env("VIRUSTOTAL_API_KEY", "")
SECURITYTRAILS_API_KEY = get_env("SECURITYTRAILS_API_KEY", "")
CENSYS_API_ID = get_env("CENSYS_API_ID", "")
CENSYS_API_SECRET = get_env("CENSYS_API_SECRET", "")

# Wordlists Paths
SUBDOMAIN_WORDLIST = get_env("SUBDOMAIN_WORDLIST", "")
DIRECTORY_WORDLIST = get_env("DIRECTORY_WORDLIST", "")

# Discord Settings
ALLOWED_CHANNELS = get_env("ALLOWED_CHANNELS", "").split(",") if get_env("ALLOWED_CHANNELS") else []
ALLOWED_ROLES = get_env("ALLOWED_ROLES", "").split(",") if get_env("ALLOWED_ROLES") else []
ADMIN_USERS = get_env("ADMIN_USERS", "").split(",") if get_env("ADMIN_USERS") else []

# Scan Limits
MAX_DOMAINS_PER_SCAN = int(get_env("MAX_DOMAINS_PER_SCAN", "100"))
MAX_URLS_PER_SCAN = int(get_env("MAX_URLS_PER_SCAN", "50"))
SCAN_COOLDOWN = int(get_env("SCAN_COOLDOWN", "5"))
