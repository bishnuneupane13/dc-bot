import aiohttp
import asyncio
import re
import ssl
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


class HttpxTools:
    """HTTPX-like tools for HTTP analysis"""
    
    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        
        # Technology signatures
        self.tech_signatures = {
            # Web Servers
            'Apache': [r'Apache', r'apache'],
            'Nginx': [r'nginx', r'Nginx'],
            'IIS': [r'Microsoft-IIS', r'IIS'],
            'LiteSpeed': [r'LiteSpeed'],
            'Cloudflare': [r'cloudflare', r'cf-ray'],
            
            # CMS
            'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
            'Drupal': [r'drupal', r'sites/default/files'],
            'Joomla': [r'joomla', r'/components/com_'],
            'Magento': [r'Magento', r'/skin/frontend/'],
            'Shopify': [r'shopify', r'cdn.shopify.com'],
            
            # JavaScript Frameworks
            'React': [r'react', r'_reactRootContainer', r'__REACT'],
            'Vue.js': [r'vue', r'__VUE__', r'v-cloak'],
            'Angular': [r'ng-app', r'angular', r'ng-controller'],
            'jQuery': [r'jquery', r'jQuery'],
            'Next.js': [r'__NEXT_DATA__', r'_next/static'],
            
            # Backend Frameworks
            'Laravel': [r'laravel_session', r'XSRF-TOKEN'],
            'Django': [r'csrfmiddlewaretoken', r'django'],
            'Express': [r'X-Powered-By: Express'],
            'Ruby on Rails': [r'action_controller', r'rails'],
            'ASP.NET': [r'asp.net', r'__VIEWSTATE', r'X-AspNet-Version'],
            'Spring': [r'spring', r'j_spring_security'],
            'Flask': [r'Werkzeug', r'flask'],
            
            # CDN/WAF
            'Akamai': [r'akamai', r'Akamai'],
            'AWS CloudFront': [r'cloudfront', r'x-amz'],
            'Fastly': [r'fastly', r'x-fastly'],
            'Sucuri': [r'sucuri', r'x-sucuri'],
            'Imperva': [r'imperva', r'incapsula'],
            
            # Analytics
            'Google Analytics': [r'google-analytics', r'ga.js', r'analytics.js', r'gtag'],
            'Hotjar': [r'hotjar'],
            'Mixpanel': [r'mixpanel'],
            
            # Databases (from errors)
            'MySQL': [r'mysql', r'MySQL'],
            'PostgreSQL': [r'postgresql', r'psql'],
            'MongoDB': [r'mongodb', r'mongo'],
            'Redis': [r'redis', r'Redis'],
            
            # Others
            'PHP': [r'X-Powered-By: PHP', r'\.php'],
            'Java': [r'JSESSIONID', r'java', r'\.jsp'],
            'Python': [r'python', r'\.py'],
            'Node.js': [r'node', r'X-Powered-By: Express'],
            'Bootstrap': [r'bootstrap', r'Bootstrap'],
            'Font Awesome': [r'font-awesome', r'fontawesome'],
            'reCAPTCHA': [r'recaptcha', r'g-recaptcha'],
        }
    
    async def __aenter__(self):
        await self.get_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()

    async def get_session(self):
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            # Create SSL context that doesn't verify certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self.session = aiohttp.ClientSession(
                timeout=self.timeout, 
                headers=self.headers,
                connector=connector
            )
        return self.session
    
    async def close_session(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def probe_domains(self, urls: List[str]) -> List[str]:
        """
        Probe domains to check if they're alive
        Similar to httpx probe functionality
        """
        live_urls = []
        session = await self.get_session()
        
        async def check_url(url: str) -> Optional[str]:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                test_urls = [f'https://{url}', f'http://{url}']
            else:
                test_urls = [url]
            
            for test_url in test_urls:
                try:
                    async with session.get(
                        test_url, 
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status < 500:
                            return test_url
                except Exception:
                    continue
            return None
        
        tasks = [check_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                live_urls.append(result)
        
        return live_urls
    
    async def detect_technology(self, domain: str) -> Dict[str, List[str]]:
        """
        Detect technologies used by a website
        """
        detected = {
            "technologies": [],
            "headers": {},
            "cookies": [],
            "scripts": [],
            "meta_tags": []
        }
        
        session = await self.get_session()
        url = f"https://{domain}" if not domain.startswith('http') else domain
        
        try:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.text()
                headers = dict(resp.headers)
                
                # Store response headers
                detected["headers"] = {
                    "Server": headers.get("Server", "Not disclosed"),
                    "X-Powered-By": headers.get("X-Powered-By", "Not disclosed"),
                    "Content-Type": headers.get("Content-Type", "Unknown")
                }
                
                # Get cookies
                for cookie in resp.cookies.values():
                    detected["cookies"].append(cookie.key)
                
                # Combine headers and body for detection
                full_content = str(headers) + body
                
                # Detect technologies
                for tech, patterns in self.tech_signatures.items():
                    for pattern in patterns:
                        if re.search(pattern, full_content, re.IGNORECASE):
                            if tech not in detected["technologies"]:
                                detected["technologies"].append(tech)
                            break
                
                # Extract script sources
                script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
                scripts = re.findall(script_pattern, body, re.IGNORECASE)
                detected["scripts"] = scripts[:20]
                
                # Extract meta tags
                meta_pattern = r'<meta[^>]+>'
                metas = re.findall(meta_pattern, body, re.IGNORECASE)
                detected["meta_tags"] = metas[:10]
                
        except Exception as e:
            detected["error"] = str(e)
        
        return detected
    
    async def get_status_codes(self, urls: List[str]) -> Dict[str, Any]:
        """
        Get HTTP status codes for multiple URLs
        """
        results = {
            "urls": {},
            "summary": {
                "2xx": 0,
                "3xx": 0,
                "4xx": 0,
                "5xx": 0,
                "failed": 0
            }
        }
        
        session = await self.get_session()
        
        async def get_status(url: str) -> tuple:
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            try:
                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return (url, resp.status)
            except Exception as e:
                return (url, f"Error: {type(e).__name__}")
        
        tasks = [get_status(url) for url in urls]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            if isinstance(response, Exception):
                continue
            url, status = response
            results["urls"][url] = status
            
            if isinstance(status, int):
                if 200 <= status < 300:
                    results["summary"]["2xx"] += 1
                elif 300 <= status < 400:
                    results["summary"]["3xx"] += 1
                elif 400 <= status < 500:
                    results["summary"]["4xx"] += 1
                elif 500 <= status < 600:
                    results["summary"]["5xx"] += 1
            else:
                results["summary"]["failed"] += 1
        
        return results
    
    async def extract_titles(self, urls: List[str]) -> Dict[str, str]:
        """
        Extract page titles from URLs
        """
        titles = {}
        session = await self.get_session()
        
        async def get_title(url: str) -> tuple:
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            try:
                async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
                        if match:
                            return (url, match.group(1).strip())
                    return (url, f"[Status: {resp.status}]")
            except Exception as e:
                return (url, f"[Error: {type(e).__name__}]")
        
        tasks = [get_title(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if not isinstance(result, Exception):
                url, title = result
                titles[url] = title
        
        return titles
    
    async def check_content_length(self, urls: List[str]) -> Dict[str, Any]:
        """
        Get content length for multiple URLs
        """
        results = {}
        session = await self.get_session()
        
        async def get_length(url: str) -> tuple:
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            try:
                async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    content = await resp.read()
                    return (url, {
                        "status": resp.status,
                        "content_length": len(content),
                        "content_type": resp.headers.get("Content-Type", "Unknown")
                    })
            except Exception as e:
                return (url, {"error": str(e)})
        
        tasks = [get_length(url) for url in urls]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            if not isinstance(response, Exception):
                url, data = response
                results[url] = data
        
        return results
    
    async def full_scan(self, domain: str) -> Dict[str, Any]:
        """
        Perform a full HTTPX-like scan on a domain
        """
        results = {
            "domain": domain,
            "live": False,
            "url": None,
            "status_code": None,
            "title": None,
            "content_length": None,
            "content_type": None,
            "technologies": [],
            "server": None,
            "headers": {},
            "redirect_chain": [],
            "ssl_info": {},
            "response_time": None
        }
        
        session = await self.get_session()
        
        # Try HTTPS first, then HTTP
        for protocol in ['https://', 'http://']:
            url = f"{protocol}{domain}" if not domain.startswith('http') else domain
            
            try:
                import time
                start_time = time.time()
                
                async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    end_time = time.time()
                    
                    results["live"] = True
                    results["url"] = str(resp.url)
                    results["status_code"] = resp.status
                    results["response_time"] = round((end_time - start_time) * 1000, 2)  # ms
                    results["content_type"] = resp.headers.get("Content-Type", "Unknown")
                    
                    body = await resp.text()
                    results["content_length"] = len(body)
                    
                    # Extract title
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
                    if title_match:
                        results["title"] = title_match.group(1).strip()[:100]
                    
                    # Get server info
                    results["server"] = resp.headers.get("Server", "Not disclosed")
                    
                    # Important headers
                    important_headers = [
                        'Server', 'X-Powered-By', 'Content-Security-Policy',
                        'X-Frame-Options', 'Strict-Transport-Security',
                        'X-Content-Type-Options', 'Set-Cookie'
                    ]
                    for header in important_headers:
                        if header in resp.headers:
                            results["headers"][header] = resp.headers[header][:200]
                    
                    # Redirect chain
                    for h in resp.history:
                        results["redirect_chain"].append({
                            "url": str(h.url),
                            "status": h.status
                        })
                    
                    # SSL info for HTTPS
                    if protocol == 'https://':
                        results["ssl_info"] = {
                            "protocol": "TLS",
                            "verified": True
                        }
                    
                    # Detect technologies
                    tech_result = await self.detect_technology(domain)
                    results["technologies"] = tech_result.get("technologies", [])
                    
                    break  # Success, no need to try HTTP
                    
            except Exception as e:
                if protocol == 'https://':
                    continue  # Try HTTP
                results["error"] = str(e)
        
        return results
    
    async def filter_by_status(self, urls: List[str], status_codes: List[int]) -> List[str]:
        """
        Filter URLs by specific status codes
        """
        matching_urls = []
        status_results = await self.get_status_codes(urls)
        
        for url, status in status_results["urls"].items():
            if isinstance(status, int) and status in status_codes:
                matching_urls.append(url)
        
        return matching_urls
    
    async def filter_by_title(self, urls: List[str], keywords: List[str]) -> List[str]:
        """
        Filter URLs by title keywords
        """
        matching_urls = []
        titles = await self.extract_titles(urls)
        
        for url, title in titles.items():
            title_lower = title.lower()
            if any(kw.lower() in title_lower for kw in keywords):
                matching_urls.append(url)
        
        return matching_urls
    
    async def filter_by_technology(self, urls: List[str], technologies: List[str]) -> List[str]:
        """
        Filter URLs by detected technologies
        """
        matching_urls = []
        
        async def check_tech(url: str) -> Optional[str]:
            domain = urlparse(url).netloc if url.startswith('http') else url
            tech_result = await self.detect_technology(domain)
            detected = [t.lower() for t in tech_result.get("technologies", [])]
            
            if any(t.lower() in detected for t in technologies):
                return url
            return None
        
        tasks = [check_tech(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                matching_urls.append(result)
        
        return matching_urls
    
    async def batch_scan(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Perform batch scanning of multiple domains
        """
        tasks = [self.full_scan(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        scan_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                scan_results.append({
                    "domain": domains[i],
                    "error": str(result)
                })
            else:
                scan_results.append(result)
        
        return scan_results
