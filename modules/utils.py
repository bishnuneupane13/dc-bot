import discord
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional


def create_embed(
    title: str,
    description: str = "",
    color: discord.Color = discord.Color.blue(),
    fields: List[Dict[str, Any]] = None,
    footer: str = None,
    thumbnail: str = None
) -> discord.Embed:
    """
    Create a Discord embed with common styling
    """
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.now()
    )
    
    if fields:
        for field in fields:
            embed.add_field(
                name=field.get("name", ""),
                value=field.get("value", ""),
                inline=field.get("inline", True)
            )
    
    if footer:
        embed.set_footer(text=footer)
    
    if thumbnail:
        embed.set_thumbnail(url=thumbnail)
    
    return embed


def save_results(data: Any, filename: str, directory: str = "results") -> str:
    """
    Save scan results to a file
    """
    # Create directory if it doesn't exist
    os.makedirs(directory, exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_filename = f"{filename}_{timestamp}.json"
    filepath = os.path.join(directory, full_filename)
    
    # Save data
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    
    return filepath


def load_results(filepath: str) -> Optional[Dict]:
    """
    Load results from a file
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading results: {e}")
        return None


def format_results_for_discord(results: Any, max_length: int = 1900) -> str:
    """
    Format results for Discord message (respecting character limit)
    """
    if isinstance(results, list):
        text = "\n".join(str(item) for item in results)
    elif isinstance(results, dict):
        text = json.dumps(results, indent=2, default=str)
    else:
        text = str(results)
    
    if len(text) > max_length:
        text = text[:max_length - 20] + "\n... (truncated)"
    
    return text


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """
    Split a list into chunks of specified size
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def parse_domains(input_text: str) -> List[str]:
    """
    Parse domains from various input formats
    """
    domains = []
    
    # Split by newlines and commas
    for line in input_text.replace(',', '\n').split('\n'):
        domain = line.strip()
        if domain:
            # Remove protocol if present
            if '://' in domain:
                domain = domain.split('://')[1]
            # Remove path if present
            domain = domain.split('/')[0]
            # Remove port if present
            domain = domain.split(':')[0]
            domains.append(domain)
    
    return list(set(domains))  # Remove duplicates


def validate_domain(domain: str) -> bool:
    """
    Basic domain validation
    """
    import re
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_url(url: str) -> bool:
    """
    Basic URL validation
    """
    import re
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url, re.IGNORECASE))


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal
    """
    import re
    # Remove path separators and other dangerous characters
    return re.sub(r'[<>:"/\\|?*]', '_', filename)


def get_severity_color(severity: str) -> discord.Color:
    """
    Get Discord color based on severity level
    """
    severity_colors = {
        "critical": discord.Color.dark_red(),
        "high": discord.Color.red(),
        "medium": discord.Color.orange(),
        "low": discord.Color.yellow(),
        "info": discord.Color.blue(),
        "safe": discord.Color.green()
    }
    return severity_colors.get(severity.lower(), discord.Color.grey())


def calculate_risk_score(vulnerabilities: List[Dict]) -> Dict[str, Any]:
    """
    Calculate overall risk score based on vulnerabilities
    """
    severity_weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1
    }
    
    total_score = 0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "info").lower()
        total_score += severity_weights.get(severity, 1)
        counts[severity] = counts.get(severity, 0) + 1
    
    # Determine overall risk level
    if counts["critical"] > 0:
        risk_level = "CRITICAL"
    elif counts["high"] > 0:
        risk_level = "HIGH"
    elif counts["medium"] > 0:
        risk_level = "MEDIUM"
    elif counts["low"] > 0:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"
    
    return {
        "score": total_score,
        "risk_level": risk_level,
        "counts": counts
    }


class RateLimiter:
    """
    Simple rate limiter for API calls
    """
    def __init__(self, calls_per_second: float = 5):
        self.calls_per_second = calls_per_second
        self.last_call = 0
    
    async def wait(self):
        """Wait if necessary to respect rate limit"""
        import asyncio
        import time
        
        now = time.time()
        time_since_last = now - self.last_call
        min_interval = 1.0 / self.calls_per_second
        
        if time_since_last < min_interval:
            await asyncio.sleep(min_interval - time_since_last)
        
        self.last_call = time.time()


class ScanProgress:
    """
    Track and report scan progress
    """
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.failed = 0
        self.start_time = datetime.now()
    
    def increment(self, success: bool = True):
        self.completed += 1
        if not success:
            self.failed += 1
    
    def get_progress(self) -> Dict[str, Any]:
        elapsed = (datetime.now() - self.start_time).total_seconds()
        rate = self.completed / elapsed if elapsed > 0 else 0
        eta = (self.total - self.completed) / rate if rate > 0 else 0
        
        return {
            "completed": self.completed,
            "total": self.total,
            "failed": self.failed,
            "percentage": round((self.completed / self.total) * 100, 1) if self.total > 0 else 0,
            "rate": round(rate, 2),
            "eta_seconds": round(eta, 0)
        }
    
    def format_progress_bar(self, width: int = 20) -> str:
        """Create a text-based progress bar"""
        percentage = self.completed / self.total if self.total > 0 else 0
        filled = int(width * percentage)
        bar = '█' * filled + '░' * (width - filled)
        return f"[{bar}] {percentage * 100:.1f}%"
