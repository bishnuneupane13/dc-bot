import os

def check_and_create_wordlists():
    """Check if wordlists exist, if not create default ones"""
    base_dir = "wordlists"
    os.makedirs(base_dir, exist_ok=True)
    
    defaults = {
        "subdomains.txt": [
            "www", "www1", "www2", "web", "2web", "mail", "mail1", "mail2", "email", "webmail",
            "smtp", "mx", "mx1", "owa", "exchange", "api", "app", "mobile", "m", "cdn",
            "cloud", "files", "file", "storage", "admin", "portal", "dashboard", "support",
            "store", "shop", "forum", "bbs", "blog", "news", "dev", "test", "stage",
            "staging", "beta", "demo", "server", "host", "remote", "vpn", "secure", "gw",
            "ftp", "upload", "downloads", "ns", "ns1", "ns2", "gov", "1", "2", "3"
        ],
        "directories.txt": [
            "admin", "administrator", "admin-panel", "dashboard", "control", "backend", "panel",
            "login", "signin", "signup", "auth", "authentication", "api", "api-v1", "api-v2",
            "api-internal", "internal-api", "graphql", "config", "configs", "configuration",
            "settings", "env", "environment", "secrets", "secret", "keys", "credentials",
            "private", "secure", "protected", "uploads", "upload", "files", "file", "media",
            "documents", "downloads", "backup", "backups", "dump", "dumps", "archive",
            "archives", "old", "legacy", "database", "databases", "db", "data", "sql", "dev",
            "development", "test", "testing", "staging", "stage", "debug", "debugging",
            "logs", "log", "history", "cache", "tmp", "temp", "scripts", "script", "bin",
            "cli", "cron", "jobs", "tasks", "user", "users", "account", "accounts", "profile",
            "profiles", "members", "cloud", "aws", "azure", "gcp", "s3", "bucket", "buckets"
        ],
        "parameters.txt": [
            "id", "user", "uid", "uuid", "account", "account_id", "role", "permission",
            "access", "token", "access_token", "refresh_token", "auth", "authorization",
            "session", "session_id", "jwt", "password", "passwd", "pwd", "secret",
            "api_key", "key", "cmd", "command", "exec", "redirect", "redirect_uri",
            "return", "callback", "file", "filename", "path", "download", "debug", "test",
            "email", "username", "name", "profile", "profile_id", "user_id", "owner",
            "owner_id", "group", "group_id", "url", "uri", "link", "view", "page", "next",
            "continue", "target", "dest", "search", "q", "query", "keyword", "filter",
            "sort", "order", "limit", "offset", "from", "to", "date", "type", "status",
            "category", "upload", "uploads", "file", "files", "image", "avatar", "photo",
            "document", "attachment", "media", "content", "data", "payload", "input",
            "body", "object", "items", "ids", "values", "meta", "config", "settings", "options"
        ]
    }
    
    created = []
    for filename, content in defaults.items():
        filepath = os.path.join(base_dir, filename)
        if not os.path.exists(filepath):
            try:
                with open(filepath, 'w') as f:
                    f.write("\n".join(content))
                created.append(filename)
            except Exception as e:
                print(f"Error creating wordlist {filename}: {e}")
                
    return created
