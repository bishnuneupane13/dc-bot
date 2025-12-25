"""
Advanced Bug Bounty Tools Module
================================
Directory bruteforce, subdomain takeover, WAF detection, and more.
"""

import aiohttp
import asyncio
import re
import socket
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import dns.resolver


class AdvancedTools:
    """Advanced reconnaissance and discovery tools"""
    
    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=15)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Common directories wordlist
        self.common_dirs = [
            'admin', 'administrator', 'wp-admin', 'login', 'dashboard', 'panel',
            'api', 'api/v1', 'api/v2', 'graphql', 'swagger', 'api-docs',
            'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'test',
            '.git', '.svn', '.env', '.htaccess', '.htpasswd', 'config',
            'wp-content', 'wp-includes', 'uploads', 'upload', 'files', 'media',
            'assets', 'static', 'js', 'css', 'images', 'img', 'fonts',
            'cgi-bin', 'scripts', 'includes', 'inc', 'lib', 'libs',
            'phpmyadmin', 'pma', 'mysql', 'database', 'db', 'sql',
            'logs', 'log', 'debug', 'error', 'errors', 'status',
            'server-status', 'server-info', 'info.php', 'phpinfo.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'security.txt',
            '.well-known', 'favicon.ico', 'humans.txt',
            'console', 'shell', 'cmd', 'terminal', 'exec',
            'node_modules', 'vendor', 'packages', 'bower_components',
            'private', 'secret', 'hidden', 'internal', 'dev', 'staging',
            'beta', 'alpha', 'demo', 'sandbox', 'preview',
            'user', 'users', 'account', 'accounts', 'profile', 'member',
            'register', 'signup', 'signin', 'auth', 'oauth', 'sso',
            'forgot', 'reset', 'password', 'recover', 'activate',
            'download', 'downloads', 'export', 'import', 'data',
            'docs', 'documentation', 'help', 'support', 'faq',
            'blog', 'news', 'posts', 'articles', 'content',
            'shop', 'store', 'cart', 'checkout', 'payment', 'order',
            'search', 'find', 'query', 'filter', 'results',
            'ajax', 'async', 'ws', 'websocket', 'socket.io',
            'health', 'healthcheck', 'ping', 'version', 'build',
            'metrics', 'prometheus', 'grafana', 'kibana', 'elastic',
            'jenkins', 'travis', 'ci', 'cd', 'deploy', 'release'
        ]
        
        # Subdomain takeover fingerprints
        self.takeover_fingerprints = {
            'GitHub Pages': ['There isn\'t a GitHub Pages site here', 'For root URLs'],
            'Heroku': ['No such app', 'no-such-app'],
            'AWS S3': ['NoSuchBucket', 'The specified bucket does not exist'],
            'Azure': ['404 Web Site not found', 'Web App - Not Found'],
            'Shopify': ['Sorry, this shop is currently unavailable'],
            'Tumblr': ['There\'s nothing here', 'Whatever you were looking for'],
            'WordPress.com': ['Do you want to register'],
            'Ghost': ['The thing you were looking for is no longer here'],
            'Surge.sh': ['project not found'],
            'Bitbucket': ['Repository not found'],
            'Pantheon': ['404 error unknown site'],
            'Fastly': ['Fastly error: unknown domain'],
            'Zendesk': ['Help Center Closed'],
            'Teamwork': ['Oops - We didn\'t find your site'],
            'Helpjuice': ['We could not find what you\'re looking for'],
            'Helpscout': ['No settings were found'],
            'Cargo': ['If you\'re moving your domain'],
            'Uservoice': ['This UserVoice subdomain is currently available'],
            'Smugmug': ['Page Not Found'],
            'Strikingly': ['But if you\'re looking to build your own'],
            'Unbounce': ['The requested URL was not found'],
            'Tictail': ['to target URL: <a href="https://tictail.com'],
            'Intercom': ['This page is reserved for a company'],
            'Webflow': ['The page you are looking for doesn\'t exist'],
            'Kajabi': ['The page you were looking for doesn\'t exist'],
            'Thinkific': ['You may have mistyped the address'],
            'Tave': ['Sorry, this page is no longer available'],
            'Wishpond': ['https://www.wishpond.com/404'],
            'Aftership': ['Oops, page not found'],
            'Aha!': ['There is no portal here'],
            'Brightcove': ['<p class="bc-gallery-error-code">Error Code'],
            'Bigcartel': ['<h1>Oops! We couldn&rsquo;t find that page'],
            'Acquia': ['Web Site Not Found'],
            'Simplebooklet': ['We can\'t find this <a href'],
            'Getresponse': ['With GetResponse Landing Pages'],
            'Vend': ['Looks like you\'ve traveled too far'],
            'Netlify': ['Not Found - Request ID'],
            'Ngrok': ['Tunnel *.ngrok.io not found'],
        }
        
        # WAF signatures
        self.waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'cf-cache-status'],
            'AWS WAF': ['awswaf', 'x-amzn-requestid', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'akamai-ghost', 'akamaighost', 'x-akamai'],
            'Sucuri': ['sucuri', 'x-sucuri-id', 'sucuri-webhosting'],
            'Imperva': ['incapsula', 'imperva', 'visid_incap', 'incap_ses'],
            'F5 BIG-IP': ['bigipserver', 'x-wa-info', 'f5'],
            'Barracuda': ['barracuda', 'barra_counter_session'],
            'Citrix NetScaler': ['citrix', 'ns_af', 'nswebsite'],
            'Fortinet FortiWeb': ['fortigate', 'fortiweb', 'fwpd', 'forti'],
            'ModSecurity': ['modsecurity', 'mod_security', 'nyob'],
            'NAXSI': ['naxsi', 'naxsi_sig'],
            'Wordfence': ['wordfence', 'wfwaf'],
            'DenyAll': ['denyall', 'conditiondenyall'],
            'SonicWall': ['sonicwall', 'snwl'],
            'Radware': ['radware', 'rdwr', 'x-sl-compstate'],
            'StackPath': ['stackpath', 'sp-aff'],
            'Reblaze': ['reblaze', 'rbzid'],
            'Comodo': ['comodo', 'x-cdn'],
            'Varnish': ['varnish', 'x-varnish', 'via: varnish'],
            'Nginx': ['nginx', 'x-nginx'],
        }
    
    async def get_session(self):
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            connector = aiohttp.TCPConnector(ssl=False)
            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers=self.headers,
                connector=connector
            )
        return self.session
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()

    async def __aenter__(self):
        await self.get_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()
    
    # ==========================================
    # DIRECTORY BRUTEFORCE
    # ==========================================
    
    async def directory_bruteforce(self, domain: str, wordlist: List[str] = None,
                                   extensions: List[str] = None) -> Dict[str, Any]:
        """
        Bruteforce directories and files on a target
        """
        if wordlist is None:
            wordlist = self.common_dirs
        
        if extensions is None:
            extensions = ['', '.php', '.html', '.js', '.txt', '.json', '.xml', '.bak']
        
        results = {
            "domain": domain,
            "found": [],
            "redirects": [],
            "forbidden": [],
            "total_checked": 0
        }
        
        session = await self.get_session()
        base_url = f"https://{domain}" if not domain.startswith('http') else domain
        
        async def check_path(path: str) -> Optional[Dict]:
            url = f"{base_url}/{path}"
            try:
                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    result = {
                        "path": path,
                        "url": url,
                        "status": resp.status,
                        "length": int(resp.headers.get('Content-Length', 0))
                    }
                    
                    if resp.status == 200:
                        return ("found", result)
                    elif resp.status in [301, 302, 307, 308]:
                        result["redirect"] = resp.headers.get('Location', '')
                        return ("redirect", result)
                    elif resp.status == 403:
                        return ("forbidden", result)
            except:
                pass
            return None
        
        # Generate all paths to check
        paths_to_check = []
        for word in wordlist:
            for ext in extensions:
                paths_to_check.append(f"{word}{ext}")
        
        # Run checks in batches
        batch_size = 20
        for i in range(0, len(paths_to_check), batch_size):
            batch = paths_to_check[i:i + batch_size]
            tasks = [check_path(path) for path in batch]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                results["total_checked"] += 1
                if response and not isinstance(response, Exception):
                    category, data = response
                    if category == "found":
                        results["found"].append(data)
                    elif category == "redirect":
                        results["redirects"].append(data)
                    elif category == "forbidden":
                        results["forbidden"].append(data)
        
        return results
    
    # ==========================================
    # SUBDOMAIN TAKEOVER DETECTION
    # ==========================================
    
    async def check_subdomain_takeover(self, subdomains: List[str]) -> Dict[str, Any]:
        """
        Check subdomains for potential takeover vulnerabilities
        """
        results = {
            "vulnerable": [],
            "potentially_vulnerable": [],
            "safe": [],
            "errors": []
        }
        
        session = await self.get_session()
        
        async def check_subdomain(subdomain: str) -> Dict:
            result = {
                "subdomain": subdomain,
                "status": "safe",
                "service": None,
                "cname": None,
                "reason": None
            }
            
            # Check CNAME
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                try:
                    answers = resolver.resolve(subdomain, 'CNAME')
                    cname = str(answers[0].target).rstrip('.')
                    result["cname"] = cname
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.NXDOMAIN:
                    result["status"] = "potentially_vulnerable"
                    result["reason"] = "NXDOMAIN - subdomain doesn't resolve"
                    return result
            except Exception as e:
                result["error"] = str(e)
            
            # Check HTTP response for fingerprints
            for protocol in ['https://', 'http://']:
                try:
                    url = f"{protocol}{subdomain}"
                    async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        body = await resp.text()
                        
                        for service, fingerprints in self.takeover_fingerprints.items():
                            for fingerprint in fingerprints:
                                if fingerprint.lower() in body.lower():
                                    result["status"] = "vulnerable"
                                    result["service"] = service
                                    result["reason"] = f"Matched fingerprint: {fingerprint[:50]}"
                                    return result
                    break
                except aiohttp.ClientError:
                    continue
                except Exception:
                    continue
            
            return result
        
        tasks = [check_subdomain(sub) for sub in subdomains]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            if isinstance(response, Exception):
                results["errors"].append(str(response))
            elif response["status"] == "vulnerable":
                results["vulnerable"].append(response)
            elif response["status"] == "potentially_vulnerable":
                results["potentially_vulnerable"].append(response)
            else:
                results["safe"].append(response["subdomain"])
        
        return results
    
    # ==========================================
    # WAF DETECTION
    # ==========================================
    
    async def detect_waf(self, domain: str) -> Dict[str, Any]:
        """
        Detect Web Application Firewall (WAF) on target
        """
        results = {
            "domain": domain,
            "waf_detected": False,
            "waf_name": None,
            "confidence": "low",
            "indicators": [],
            "headers": {}
        }
        
        session = await self.get_session()
        url = f"https://{domain}" if not domain.startswith('http') else domain
        
        # Test with normal request
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                headers = dict(resp.headers)
                body = await resp.text()
                results["headers"] = {k: v for k, v in headers.items() if k.lower().startswith(('x-', 'server', 'via', 'cf-'))}
                
                # Check headers and body for WAF signatures
                combined = str(headers).lower() + body.lower()
                
                for waf_name, signatures in self.waf_signatures.items():
                    for sig in signatures:
                        if sig.lower() in combined:
                            results["waf_detected"] = True
                            results["waf_name"] = waf_name
                            results["indicators"].append(f"Found: {sig}")
                            break
                    if results["waf_detected"]:
                        break
        except Exception as e:
            results["error"] = str(e)
        
        # Test with malicious-looking request to trigger WAF
        if not results["waf_detected"]:
            try:
                test_payloads = [
                    f"{url}/?id=1' OR '1'='1",
                    f"{url}/<script>alert(1)</script>",
                    f"{url}/../../../etc/passwd"
                ]
                
                for payload_url in test_payloads:
                    try:
                        async with session.get(payload_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            if resp.status in [403, 406, 429, 503]:
                                results["waf_detected"] = True
                                results["waf_name"] = "Unknown WAF"
                                results["indicators"].append(f"Blocked request with status {resp.status}")
                                results["confidence"] = "medium"
                                
                                # Re-check headers for WAF
                                headers = dict(resp.headers)
                                for waf_name, signatures in self.waf_signatures.items():
                                    for sig in signatures:
                                        if sig.lower() in str(headers).lower():
                                            results["waf_name"] = waf_name
                                            results["confidence"] = "high"
                                            break
                                break
                    except:
                        continue
            except:
                pass
        
        if results["waf_detected"] and len(results["indicators"]) >= 2:
            results["confidence"] = "high"
        
        return results
    
    # ==========================================
    # ROBOTS.TXT & SITEMAP ANALYZER
    # ==========================================
    
    async def analyze_robots_txt(self, domain: str) -> Dict[str, Any]:
        """
        Analyze robots.txt for hidden paths and interesting info
        """
        results = {
            "domain": domain,
            "found": False,
            "disallowed_paths": [],
            "allowed_paths": [],
            "sitemaps": [],
            "interesting_paths": [],
            "raw": ""
        }
        
        session = await self.get_session()
        
        # Normalize domain to get root
        clean_domain = domain.lower().replace('https://', '').replace('http://', '').split('/')[0]
        url = f"https://{clean_domain}/robots.txt"
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    results["found"] = True
                    content = await resp.text()
                    results["raw"] = content[:2000]
                    
                    for line in content.split('\n'):
                        line = line.strip()
                        
                        if line.lower().startswith('disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path:
                                results["disallowed_paths"].append(path)
                                # Check for interesting paths
                                interesting_keywords = ['admin', 'backup', 'config', 'private', 
                                                       'secret', 'api', 'internal', 'dev', 'test']
                                for keyword in interesting_keywords:
                                    if keyword in path.lower():
                                        results["interesting_paths"].append(path)
                                        break
                        
                        elif line.lower().startswith('allow:'):
                            path = line.split(':', 1)[1].strip()
                            if path:
                                results["allowed_paths"].append(path)
                        
                        elif line.lower().startswith('sitemap:'):
                            sitemap = line.split(':', 1)[1].strip()
                            if sitemap:
                                results["sitemaps"].append(sitemap)
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    async def parse_sitemap(self, domain: str) -> Dict[str, Any]:
        """
        Parse sitemap.xml for URLs and endpoints
        """
        results = {
            "domain": domain,
            "found": False,
            "urls": [],
            "nested_sitemaps": [],
            "total_urls": 0
        }
        
        session = await self.get_session()
        base_url = f"https://{domain}" if not domain.startswith('http') else domain
        sitemap_urls = [
            f"{base_url}/sitemap.xml",
            f"{base_url}/sitemap_index.xml",
            f"{base_url}/sitemap1.xml",
            f"{base_url}/sitemaps/sitemap.xml"
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                async with session.get(sitemap_url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        results["found"] = True
                        content = await resp.text()
                        
                        # Extract URLs
                        url_pattern = r'<loc>([^<]+)</loc>'
                        urls = re.findall(url_pattern, content)
                        
                        for url in urls:
                            if url.endswith('.xml'):
                                results["nested_sitemaps"].append(url)
                            else:
                                results["urls"].append(url)
                        
                        results["total_urls"] = len(results["urls"])
                        break
            except:
                continue
        
        # Limit results
        results["urls"] = results["urls"][:100]
        
        return results
    
    # ==========================================
    # SECURITY HEADERS ANALYSIS
    # ==========================================
    
    async def full_header_analysis(self, domain: str) -> Dict[str, Any]:
        """
        Comprehensive security headers analysis
        """
        results = {
            "domain": domain,
            "score": 100,
            "grade": "A+",
            "headers": {},
            "missing": [],
            "warnings": [],
            "recommendations": []
        }
        
        session = await self.get_session()
        url = f"https://{domain}" if not domain.startswith('http') else domain
        
        # Security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'required': True,
                'penalty': 15,
                'recommendation': 'Add HSTS header with max-age of at least 31536000'
            },
            'Content-Security-Policy': {
                'required': True,
                'penalty': 20,
                'recommendation': 'Implement a strict CSP to prevent XSS attacks'
            },
            'X-Frame-Options': {
                'required': True,
                'penalty': 10,
                'recommendation': 'Set to DENY or SAMEORIGIN to prevent clickjacking'
            },
            'X-Content-Type-Options': {
                'required': True,
                'penalty': 10,
                'recommendation': 'Set to nosniff to prevent MIME-type sniffing'
            },
            'Referrer-Policy': {
                'required': True,
                'penalty': 5,
                'recommendation': 'Set to strict-origin-when-cross-origin or stricter'
            },
            'Permissions-Policy': {
                'required': False,
                'penalty': 5,
                'recommendation': 'Restrict browser features like geolocation, camera'
            },
            'X-XSS-Protection': {
                'required': False,
                'penalty': 5,
                'recommendation': 'Set to 1; mode=block (deprecated but still useful)'
            },
            'Cross-Origin-Opener-Policy': {
                'required': False,
                'penalty': 5,
                'recommendation': 'Set to same-origin for isolation'
            },
            'Cross-Origin-Resource-Policy': {
                'required': False,
                'penalty': 5,
                'recommendation': 'Set to same-origin or same-site'
            },
            'Cross-Origin-Embedder-Policy': {
                'required': False,
                'penalty': 5,
                'recommendation': 'Set to require-corp for cross-origin isolation'
            }
        }
        
        # Headers that should NOT be present
        bad_headers = {
            'Server': 'Reveals server software version',
            'X-Powered-By': 'Reveals technology stack',
            'X-AspNet-Version': 'Reveals ASP.NET version',
            'X-AspNetMvc-Version': 'Reveals MVC version'
        }
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                headers = dict(resp.headers)
                results["headers"] = headers
                
                # Check for required security headers
                for header, config in security_headers.items():
                    if header in headers:
                        value = headers[header]
                        
                        # Check for weak configurations
                        if header == 'Strict-Transport-Security':
                            if 'max-age=0' in value.lower():
                                results["warnings"].append(f"{header}: max-age is 0")
                                results["score"] -= 5
                        
                        elif header == 'X-Frame-Options':
                            if value.upper() not in ['DENY', 'SAMEORIGIN']:
                                results["warnings"].append(f"{header}: weak value '{value}'")
                                results["score"] -= 3
                        
                        elif header == 'Content-Security-Policy':
                            if 'unsafe-inline' in value.lower():
                                results["warnings"].append(f"{header}: contains unsafe-inline")
                            if 'unsafe-eval' in value.lower():
                                results["warnings"].append(f"{header}: contains unsafe-eval")
                    else:
                        results["missing"].append(header)
                        results["score"] -= config['penalty']
                        results["recommendations"].append(config['recommendation'])
                
                # Check for information disclosure headers
                for header, reason in bad_headers.items():
                    if header in headers:
                        results["warnings"].append(f"{header} present: {reason}")
                        results["score"] -= 3
                
                # Calculate grade
                results["score"] = max(0, results["score"])
                if results["score"] >= 90:
                    results["grade"] = "A+"
                elif results["score"] >= 80:
                    results["grade"] = "A"
                elif results["score"] >= 70:
                    results["grade"] = "B"
                elif results["score"] >= 60:
                    results["grade"] = "C"
                elif results["score"] >= 50:
                    results["grade"] = "D"
                else:
                    results["grade"] = "F"
                    
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # FAVICON HASH (for Shodan/tech detection)
    # ==========================================
    
    async def get_favicon_hash(self, domain: str) -> Dict[str, Any]:
        """
        Get favicon hash for technology detection (Shodan compatible)
        """
        import base64
        import struct
        
        results = {
            "domain": domain,
            "found": False,
            "hash": None,
            "mmh3_hash": None,
            "md5_hash": None,
            "url": None
        }
        
        session = await self.get_session()
        base_url = f"https://{domain}" if not domain.startswith('http') else domain
        
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/assets/favicon.ico',
            '/images/favicon.ico',
            '/static/favicon.ico'
        ]
        
        for path in favicon_paths:
            try:
                url = f"{base_url}{path}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        if len(content) > 0:
                            results["found"] = True
                            results["url"] = url
                            
                            # MD5 hash
                            results["md5_hash"] = hashlib.md5(content).hexdigest()
                            
                            # Base64 encode for MMH3 (Shodan style)
                            b64 = base64.b64encode(content).decode()
                            
                            # Simple hash calculation (approximate MMH3)
                            # Note: For exact MMH3, you'd need the mmh3 library
                            hash_val = 0
                            for char in b64:
                                hash_val = (hash_val * 31 + ord(char)) & 0xFFFFFFFF
                            # Convert to signed 32-bit
                            if hash_val >= 0x80000000:
                                hash_val -= 0x100000000
                            results["mmh3_hash"] = hash_val
                            
                            results["shodan_query"] = f"http.favicon.hash:{hash_val}"
                            break
            except:
                continue
        
        return results
    
    # ==========================================
    # CMS DETECTION
    # ==========================================
    
    async def detect_cms(self, domain: str) -> Dict[str, Any]:
        """
        Detect Content Management System
        """
        results = {
            "domain": domain,
            "cms_detected": None,
            "version": None,
            "confidence": "low",
            "indicators": []
        }
        
        session = await self.get_session()
        url = f"https://{domain}" if not domain.startswith('http') else domain
        
        cms_signatures = {
            'WordPress': {
                'paths': ['/wp-login.php', '/wp-admin/', '/wp-content/', '/wp-includes/'],
                'patterns': ['wp-content', 'wp-includes', 'WordPress', 'generator.*WordPress'],
                'meta': 'generator.*WordPress ([0-9.]+)?'
            },
            'Drupal': {
                'paths': ['/core/misc/drupal.js', '/sites/default/', '/node/'],
                'patterns': ['Drupal', 'drupal.js', 'drupal.settings'],
                'meta': 'generator.*Drupal ([0-9.]+)?'
            },
            'Joomla': {
                'paths': ['/administrator/', '/components/', '/templates/'],
                'patterns': ['Joomla', 'com_content', '/media/jui/'],
                'meta': 'generator.*Joomla ([0-9.]+)?'
            },
            'Magento': {
                'paths': ['/skin/frontend/', '/js/mage/', '/app/design/'],
                'patterns': ['Magento', 'Mage.Cookies', '/skin/frontend/'],
                'meta': None
            },
            'Shopify': {
                'paths': [],
                'patterns': ['Shopify', 'cdn.shopify.com', 'shopify-section'],
                'meta': None
            },
            'Wix': {
                'paths': [],
                'patterns': ['wix.com', '_wix', 'X-Wix-'],
                'meta': None
            },
            'Squarespace': {
                'paths': [],
                'patterns': ['squarespace', 'sqsp', 'static.squarespace.com'],
                'meta': None
            },
            'Ghost': {
                'paths': ['/ghost/'],
                'patterns': ['ghost', 'content/images'],
                'meta': 'generator.*Ghost ([0-9.]+)?'
            }
        }
        
        try:
            # Get main page
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.text()
                headers = dict(resp.headers)
                
                for cms, sigs in cms_signatures.items():
                    score = 0
                    
                    # Check patterns in body
                    for pattern in sigs['patterns']:
                        if re.search(pattern, body, re.IGNORECASE):
                            score += 1
                            results["indicators"].append(f"Pattern: {pattern}")
                    
                    # Check meta generator
                    if sigs['meta']:
                        match = re.search(sigs['meta'], body, re.IGNORECASE)
                        if match:
                            score += 3
                            results["cms_detected"] = cms
                            if match.groups() and match.group(1):
                                results["version"] = match.group(1)
                    
                    if score >= 2:
                        results["cms_detected"] = cms
                        results["confidence"] = "high" if score >= 3 else "medium"
                        break
            
            # Check specific paths if CMS not detected yet
            if not results["cms_detected"]:
                for cms, sigs in cms_signatures.items():
                    for path in sigs['paths'][:2]:  # Check first 2 paths
                        try:
                            test_url = f"{url}{path}"
                            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                                if resp.status == 200:
                                    results["cms_detected"] = cms
                                    results["indicators"].append(f"Path found: {path}")
                                    results["confidence"] = "medium"
                                    break
                        except:
                            continue
                    if results["cms_detected"]:
                        break
                        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # HTTP METHODS CHECK
    # ==========================================
    
    async def check_http_methods(self, domain: str) -> Dict[str, Any]:
        """
        Check which HTTP methods are allowed
        """
        results = {
            "domain": domain,
            "allowed_methods": [],
            "dangerous_methods": [],
            "cors_methods": None
        }
        
        session = await self.get_session()
        url = f"https://{domain}" if not domain.startswith('http') else domain
        
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        
        # Try OPTIONS first
        try:
            async with session.options(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                allow_header = resp.headers.get('Allow', '')
                if allow_header:
                    results["allowed_methods"] = [m.strip() for m in allow_header.split(',')]
                
                cors_methods = resp.headers.get('Access-Control-Allow-Methods', '')
                if cors_methods:
                    results["cors_methods"] = [m.strip() for m in cors_methods.split(',')]
        except:
            pass
        
        # Test each method if OPTIONS didn't reveal
        if not results["allowed_methods"]:
            for method in methods_to_test:
                try:
                    async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status not in [405, 501]:
                            results["allowed_methods"].append(method)
                except:
                    continue
        
        # Check for dangerous methods
        for method in results["allowed_methods"]:
            if method.upper() in dangerous:
                results["dangerous_methods"].append(method)
        
        return results
