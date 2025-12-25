"""
PASSIVE Vulnerability Scanner Module
====================================
Strictly READ-ONLY analysis of URLs, parameters, and headers.
NO payloads, NO fuzzy injection, NO active exploitation.
Identifies POTENTIAL issues based on patterns only.
"""

import aiohttp
import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import re
from datetime import datetime

class VulnScanner:
    """
    Passive analysis tool that identifies potential security hotspots
    without sending any active payloads.
    """
    
    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=15)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        }
    
    async def __aenter__(self):
        await self.get_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()
        
    async def get_session(self):
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(timeout=self.timeout, headers=self.headers)
        return self.session

    async def close_session(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for potentially risky parameters and misconfigurations.
        Passively checks query strings and response headers.
        """
        results = {
            "url": url,
            "potential_issues": [],
            "interesting_params": [],
            "security_headers": {},
            "timestamp": datetime.now().isoformat()
        }
        
        # 1. Parameter Analysis
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        risky_params = {
            'redirect': ['url', 'redirect', 'next', 'dest', 'target', 'link', 'out', 'view', 'to', 'ref', 'source'],
            'lfi': ['file', 'doc', 'path', 'root', 'page', 'include', 'template', 'layout', 'config'],
            'ssrf': ['feed', 'host', 'port', 'proxy', 'auth', 'webhook', 'callback', 'val', 'validate'],
            'sqli': ['id', 'user', 'cat', 'q', 'query', 'search', 'order', 'limit', 'filter', 'where'],
            'xss': ['msg', 'err', 'status', 'name', 'title', 'content', 'callback', 'jsonp']
        }
        
        for param in params.keys():
            param_lower = param.lower()
            for vuln_type, keywords in risky_params.items():
                if any(k in param_lower for k in keywords):
                    issue = {
                        "type": f"Potential {vuln_type.upper()} Parameter",
                        "parameter": param,
                        "description": f"The parameter '{param}' is often used in {vuln_type.upper()} vulnerabilities.",
                        "severity": "Low (Info)",
                        "action": "Manual Review Required"
                    }
                    results["potential_issues"].append(issue)
                    results["interesting_params"].append(param)

        # 2. Header Analysis (Passive)
        try:
            session = await self.get_session()
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                headers = dict(resp.headers)
                results["security_headers"] = self._check_security_headers(headers)
                
                # Check for information disclosure in headers
                if 'Server' in headers:
                    results["potential_issues"].append({
                        "type": "Information Disclosure",
                        "description": f"Server header detected: {headers['Server']}",
                        "severity": "Low",
                        "action": "Verify if version info is exposed"
                    })
                if 'X-Powered-By' in headers:
                    results["potential_issues"].append({
                        "type": "Information Disclosure",
                        "description": f"X-Powered-By header detected: {headers['X-Powered-By']}",
                        "severity": "Low",
                        "action": "Verify if technology info is exposed"
                    })
                    
        except Exception as e:
            results["error"] = str(e)

        return results

    def _check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check for presence of common security headers"""
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]
        
        status = {}
        for header in security_headers:
            if header in headers:
                status[header] = {"present": True, "value": headers[header]}
            else:
                status[header] = {"present": False, "value": None}
        return status

    # Backward compatibility wrappers (so existing code doesn't break immediately, but does nothing active)
    async def xss_scan(self, url: str): return await self.analyze_url(url)
    async def sqli_scan(self, url: str): return await self.analyze_url(url)
    async def lfi_scan(self, url: str): return await self.analyze_url(url)
    async def open_redirect_scan(self, url: str): return await self.analyze_url(url)
    async def ssrf_scan(self, url: str): return await self.analyze_url(url)
    async def cors_check(self, url: str): return await self.analyze_url(url) # Can be refined to just check headers
    async def header_check(self, url: str): return await self.analyze_url(url)
