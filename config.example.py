# ===============================================
# Bug Bounty Discord Bot Configuration (TEMPLATE)
# Rename this to config.py and fill in your values
# ===============================================

# Discord Bot Token (REQUIRED)
BOT_TOKEN = "YOUR_DISCORD_BOT_TOKEN_HERE"

COMMAND_PREFIX = "!"
BOT_STATUS = "Bug Bounty Tools"

# Scan Settings
MAX_CONCURRENT_REQUESTS = 10
REQUEST_TIMEOUT = 30
RATE_LIMIT = 5

# Logging Settings
DEBUG = False
LOG_FILE = "bot.log"

# Result Settings
RESULTS_DIR = "results"
MAX_RESULTS_DISPLAY = 50

# API Keys (Optional)
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
SECURITYTRAILS_API_KEY = "YOUR_SECURITYTRAILS_API_KEY"
CENSYS_API_ID = "YOUR_CENSYS_API_ID"
CENSYS_API_SECRET = "YOUR_CENSYS_API_SECRET"

# Wordlists Paths (Optional)
SUBDOMAIN_WORDLIST = ""
DIRECTORY_WORDLIST = ""

# Discord Settings
ALLOWED_CHANNELS = []
ALLOWED_ROLES = []
ADMIN_USERS = []

# Scan Limits
MAX_DOMAINS_PER_SCAN = 100
MAX_URLS_PER_SCAN = 50
SCAN_COOLDOWN = 5
