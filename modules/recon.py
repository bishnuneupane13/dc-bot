import aiohttp
import asyncio
import socket
import dns.resolver
import subprocess
import re
import json
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse


class ReconTools:
    """Reconnaissance tools for bug bounty hunting"""
    
    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
    
    async def __aenter__(self):
        await self.get_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()
    
    async def get_session(self):
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(timeout=self.timeout, headers=self.headers)
        return self.session
    
    async def close_session(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def subdomain_enum(self, domain: str) -> List[str]:
        """
        Enumerate subdomains using multiple sources
        """
        subdomains = set()
        
        # Use multiple APIs for subdomain enumeration
        apis = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            f"https://rapiddns.io/subdomain/{domain}?full=1#result",
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
        ]
        
        session = await self.get_session()
        
        # Query crt.sh
        try:
            async with session.get(f"https://crt.sh/?q=%.{domain}&output=json") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub and '*' not in sub:
                                subdomains.add(sub)
        except Exception as e:
            pass
        
        # Query HackerTarget
        try:
            async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip()
                            if sub:
                                subdomains.add(sub)
        except Exception as e:
            pass
        
        # Query AlienVault OTX
        try:
            async with session.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data.get('passive_dns', []):
                        hostname = entry.get('hostname', '')
                        if hostname and domain in hostname:
                            subdomains.add(hostname)
        except Exception as e:
            pass
        
        # Query ThreatMiner
        try:
            async with session.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for sub in data.get('results', []):
                        if sub:
                            subdomains.add(sub)
        except Exception as e:
            pass
        
        # Common subdomain wordlist brute force
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'api', 'dev', 'staging', 'test',
            'portal', 'app', 'm', 'mobile', 'shop', 'store', 'cdn', 'media', 'img',
            'images', 'static', 'assets', 'ns1', 'ns2', 'vpn', 'remote', 'secure',
            'dashboard', 'panel', 'login', 'auth', 'sso', 'id', 'accounts', 'account',
            'beta', 'alpha', 'demo', 'stage', 'stg', 'prod', 'production', 'internal',
            'docs', 'doc', 'help', 'support', 'status', 'monitoring', 'grafana',
            'jenkins', 'gitlab', 'git', 'svn', 'ci', 'cd', 'build', 'deploy',
            'aws', 's3', 'cloud', 'backup', 'backups', 'db', 'database', 'sql',
            'mysql', 'postgres', 'redis', 'elastic', 'kibana', 'logs', 'log'
        ]
        
        # DNS resolution for common subdomains
        tasks = []
        for sub in common_subs:
            full_domain = f"{sub}.{domain}"
            tasks.append(self._resolve_dns(full_domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if result and not isinstance(result, Exception):
                subdomains.add(f"{common_subs[i]}.{domain}")
        
        return sorted(list(subdomains))
    
    async def _resolve_dns(self, domain: str) -> Optional[str]:
        """Resolve DNS for a domain"""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, domain)
            return domain
        except:
            return None
    
    async def check_live_domains(self, domains: List[str]) -> List[str]:
        """
        Check which domains are live/responding
        """
        live_domains = []
        session = await self.get_session()
        
        async def check_domain(domain: str) -> Optional[str]:
            for protocol in ['https://', 'http://']:
                url = f"{protocol}{domain}" if not domain.startswith('http') else domain
                try:
                    async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status < 500:
                            return url
                except:
                    continue
            return None
        
        tasks = [check_domain(d) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                live_domains.append(result)
        
        return live_domains
    
    async def port_scan(self, domain: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Scan common ports on a domain
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                    993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888]
        
        open_ports = []
        closed_ports = []
        
        async def scan_port(port: int) -> tuple:
            try:
                loop = asyncio.get_event_loop()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(domain, port),
                    timeout=3
                )
                writer.close()
                await writer.wait_closed()
                return (port, True)
            except:
                return (port, False)
        
        tasks = [scan_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if not isinstance(result, Exception):
                port, is_open = result
                if is_open:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
        
        return {
            "domain": domain,
            "open_ports": sorted(open_ports),
            "closed_ports": sorted(closed_ports),
            "total_scanned": len(ports)
        }
    
    async def dns_records(self, domain: str) -> Dict[str, Any]:
        """
        Get DNS records for a domain
        """
        records = {
            "domain": domain,
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": [],
            "SOA": []
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                # Run synchronous resolver in a thread to avoid blocking the event loop
                answers = await asyncio.to_thread(resolver.resolve, domain, record_type)
                for rdata in answers:
                    records[record_type].append(str(rdata))
            except Exception:
                pass
        
        return records
    
    async def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup using API
        """
        session = await self.get_session()
        
        try:
            # Using WHOIS API
            async with session.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data
        except:
            pass
        
        # Fallback: basic info
        try:
            async with session.get(f"https://api.hackertarget.com/whois/?q={domain}") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    return {"raw": text}
        except:
            pass
        
        return {"error": "WHOIS lookup failed"}
    
    async def reverse_ip(self, domain: str) -> List[str]:
        """
        Find other domains on the same IP
        """
        domains = []
        session = await self.get_session()
        
        # Get IP first
        try:
            ip = socket.gethostbyname(domain)
        except:
            return ["Could not resolve IP"]
        
        # Query reverse IP services
        try:
            async with session.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    domains = [d.strip() for d in text.split('\n') if d.strip()]
        except:
            pass
        
        return domains
    
    async def find_parameters(self, domain: str) -> List[str]:
        """
        Find URL parameters from various sources
        """
        params = set()
        session = await self.get_session()
        
        # Get URLs from Wayback Machine
        try:
            async with session.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[1:]:  # Skip header
                        url = entry[0]
                        # Extract parameters
                        if '?' in url:
                            param_str = url.split('?')[1]
                            for param in param_str.split('&'):
                                if '=' in param:
                                    param_name = param.split('=')[0]
                                    params.add(param_name)
        except:
            pass
        
        return sorted(list(params))
    
    async def wayback_urls(self, domain: str) -> List[str]:
        """
        Get URLs from Wayback Machine
        """
        urls = []
        session = await self.get_session()
        
        try:
            async with session.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[1:]:
                        urls.append(entry[0])
        except:
            pass
        
        return urls[:500]  # Limit results
    
    async def find_js_files(self, domain: str) -> List[str]:
        """
        Find JavaScript files from a domain
        """
        js_files = set()
        session = await self.get_session()
        
        # Get from Wayback Machine
        try:
            async with session.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*.js&output=json&fl=original&collapse=urlkey"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data[1:]:
                        js_files.add(entry[0])
        except:
            pass
        
        # Crawl main page for JS
        try:
            async with session.get(f"https://{domain}") as resp:
                if resp.status == 200:
                    html = await resp.text()
                    # Find script sources
                    pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
                    matches = re.findall(pattern, html, re.IGNORECASE)
                    for match in matches:
                        if match.startswith('//'):
                            js_files.add('https:' + match)
                        elif match.startswith('/'):
                            js_files.add(f'https://{domain}{match}')
                        elif match.startswith('http'):
                            js_files.add(match)
                        else:
                            js_files.add(f'https://{domain}/{match}')
        except:
            pass
        
        return sorted(list(js_files))
    
    async def extract_endpoints(self, domain: str) -> List[str]:
        """
        Extract API endpoints from JS files and responses
        """
        endpoints = set()
        session = await self.get_session()
        
        # Patterns for endpoint discovery
        patterns = [
            r'["\']/(api|v[0-9]|graphql)[^"\']*["\']',
            r'["\'][^"\']*/(users?|admin|auth|login|register|account)[^"\']*["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']'
        ]
        
        try:
            async with session.get(f"https://{domain}") as resp:
                if resp.status == 200:
                    html = await resp.text()
                    for pattern in patterns:
                        matches = re.findall(pattern, html)
                        for match in matches:
                            if isinstance(match, tuple):
                                for m in match:
                                    if m and m.startswith('/'):
                                        endpoints.add(m)
                            elif match.startswith('/'):
                                endpoints.add(match)
        except:
            pass
        
        return sorted(list(endpoints))
    
    async def crawl_links(self, domain: str, max_depth: int = 2) -> List[str]:
        """
        Crawl and extract links from a domain
        """
        links = set()
        visited = set()
        session = await self.get_session()
        
        async def crawl(url: str, depth: int):
            if depth > max_depth or url in visited:
                return
            visited.add(url)
            
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        # Extract links
                        pattern = r'href=["\']([^"\']+)["\']'
                        matches = re.findall(pattern, html)
                        for match in matches:
                            if match.startswith('/'):
                                full_url = f"https://{domain}{match}"
                            elif match.startswith('http') and domain in match:
                                full_url = match
                            else:
                                continue
                            
                            links.add(full_url)
                            if depth < max_depth:
                                await crawl(full_url, depth + 1)
            except:
                pass
        
        await crawl(f"https://{domain}", 0)
        return sorted(list(links))[:200]
    
    async def find_secrets_for_domain(self, domain: str) -> List[Dict[str, Any]]:
        """
        Find potential secrets by fetching domain content and its JS files.
        """
        all_secrets = []
        session = await self.get_session()
        
        # 1. Check main page
        try:
            async with session.get(f"https://{domain}", timeout=10) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    all_secrets.extend(self.find_secrets(content, source=f"https://{domain}"))
        except:
            pass
            
        # 2. Check JS files (limit to first 5 for speed)
        js_files = await self.find_js_files(domain)
        for js_url in js_files[:5]:
            try:
                async with session.get(js_url, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        all_secrets.extend(self.find_secrets(content, source=js_url))
            except:
                continue
                
        return all_secrets[:50]

    def find_secrets(self, content: str, source: str = "Unknown") -> List[Dict[str, Any]]:
        """
        Find potential secrets in a raw string (JS content, HTML, etc).
        Returns list of findings with procedures.
        """
        secrets = []
        
        # Expanded patterns for secret detection
        patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'GitHub Token': r'gh[ps]_[0-9A-Za-z]{36}',
            'Slack Token': r'xox[baprs]-[0-9A-Za-z]{10,48}',
            'Firebase URL': r'[a-z0-9.-]+\.firebaseio\.com',
            'Cloudinary': r'cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-z0-9-]+',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'Heroku API Key': r'[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Private Key': r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
            'JWT Token': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*',
            'Env File Reference': r'["\']\.env["\']',
            'Debug/Admin Path': r'["\']/(debug|test|dev|config|setup|admin|management)/[a-zA-Z0-9/._-]*["\']',
            'API Key Generic': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{20,}["\']?',
            'Bearer Token': r'[Bb]earer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*'
        }
        
        unique_matches = set()
        
        for secret_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            for match in matches:
                if match in unique_matches: continue
                unique_matches.add(match)
                
                # Manual Test Procedure
                procedure = "📖 **Manual Check**: "
                if 'firebase' in secret_type.lower():
                    procedure += f"Check permissions at `https://{match}/.json` to see if it's public. "
                elif 'api key' in secret_type.lower():
                    procedure += "Use the key with the official CLI or a simple `curl` request to the service to verify validity. "
                elif 'env' in secret_type.lower():
                    procedure += "Attempt to fetch `.env` directly from the server root or the directory this file was found in. "
                elif 'path' in secret_type.lower():
                    # Strip quotes from match for the URL
                    clean_match = match.strip("' ")
                    procedure += f"Visit `{clean_match}` to see if it's an exposed dashboard. "
                else:
                    procedure += "Verify if the credential corresponds to an active service and check for restricted permissions."

                secrets.append({
                    "type": secret_type,
                    "value": match[:50] + "..." if len(match) > 50 else match,
                    "source": source,
                    "procedure": procedure
                })
        
        return secrets
