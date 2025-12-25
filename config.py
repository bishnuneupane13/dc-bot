# ===============================================
# Bug Bounty Discord Bot Configuration
# ===============================================

# Discord Bot Token (REQUIRED)
# Get your token from: https://discord.com/developers/applications
BOT_TOKEN = "MTQ1MzQ0MTA3NjgxMDc0NDAxNA.GjZ1gr.ISP7LJzlZQ4Fs_yu4lZyCau2QAzNU0gY9tYe48"

# ===============================================
# Bot Settings
# ===============================================

# Command prefix for legacy commands (if used)
COMMAND_PREFIX = "!"

# Bot activity status
BOT_STATUS = "Bug Bounty Tools"

# ===============================================
# Scan Settings
# ===============================================

# Maximum concurrent requests
MAX_CONCURRENT_REQUESTS = 10

# Request timeout in seconds
REQUEST_TIMEOUT = 30

# Rate limiting (requests per second)
RATE_LIMIT = 5

# ===============================================
# Logging Settings
# ===============================================

# Enable debug logging
DEBUG = False

# Log file path
LOG_FILE = "bot.log"

# ===============================================
# Result Settings
# ===============================================

# Results directory
RESULTS_DIR = "results"

# Maximum results to display in Discord
MAX_RESULTS_DISPLAY = 50

# ===============================================
# API Keys (Optional - for enhanced features)
# ===============================================

# Shodan API Key (for enhanced port scanning)
SHODAN_API_KEY = "jXGnLrxfCUU1XcRkWdX6oyx0zgPduVdZ"

# VirusTotal API Key (for URL scanning)
VIRUSTOTAL_API_KEY = "08598622952d30e316f78c464a5c70a18d382aa50148ab9d7dea42b57bdd1d23"

# SecurityTrails API Key (for subdomain enumeration)
SECURITYTRAILS_API_KEY = "kifuJPHsDJxMfM3_poCFgq5eKOvMmVtH"

# Censys API (for certificate transparency)
CENSYS_API_ID = "censys_DsnqNHbw_PzWeRmde5Md4aPHi8PwWe85t"
CENSYS_API_SECRET = "censys_1234567890"

# ===============================================
# Wordlists Paths (Optional)
# ===============================================

# Custom subdomain wordlist
SUBDOMAIN_WORDLIST = ""

# Custom directory wordlist
DIRECTORY_WORDLIST = ""

# ===============================================
# Discord Settings
# ===============================================

# Allowed channels (leave empty for all channels)
# Example: ["123456789", "987654321"]
ALLOWED_CHANNELS = []

# Allowed roles (leave empty for all users)
# Example: ["bug_hunter", "admin"]
ALLOWED_ROLES = []

# Admin user IDs (for admin-only commands)
ADMIN_USERS = []

# ===============================================
# Scan Limits (to prevent abuse)
# ===============================================

# Maximum domains per scan
MAX_DOMAINS_PER_SCAN = 100

# Maximum URLs per vulnerability scan
MAX_URLS_PER_SCAN = 50

# Cooldown between scans (seconds)
SCAN_COOLDOWN = 5
