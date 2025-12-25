"""
Smart Vulnerability Analysis Module
===================================
Provides "AI-like" insight by analyzing patterns, technologies, and headers
to suggest potential vulnerabilities and manual testing steps.
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

class SmartAnalyzer:
    """
    Analyzes reconnaissance data to generate smart, context-aware suggestions.
    Mimics 'AI' reasoning using heuristics and knowledge bases.
    """
    
    def __init__(self):
        # Technology-to-Vulnerability Mapping (Passive Intelligence)
        self.tech_intel = {
            "WordPress": {
                "risk": "High",
                "checks": ["/xmlrpc.php", "/wp-json/wp/v2/users", "/wp-login.php", "/license.txt"],
                "procedure": "1. Check if `/xmlrpc.php` is enabled (POST request with `system.listMethods`).\n2. Enumerate users via `/wp-json/wp/v2/users`.\n3. Search for publicly accessible backup files like `wp-config.php.bak`."
            },
            "Apache": {
                "risk": "Medium",
                "checks": [".htaccess", ".htpasswd", "server-status"],
                "procedure": "1. Check for `/server-status` for internal information disclosure.\n2. Attempt to access `.htaccess` or `.htpasswd` to check for misconfigurations.\n3. Look for directory listing on common folders."
            },
            "Nginx": {
                "risk": "Low",
                "checks": [],
                "procedure": "1. Check for missing security headers (Nginx defaults are often bare).\n2. Test for CRLF injection in headers.\n3. Check for path traversal misconfigurations like `location /alias { alias /path/to/files/; }` (missing trailing slash)."
            },
            "Firebase": {
                "risk": "High",
                "checks": [".firebaseio.com/.json"],
                "procedure": "1. Append `.json` to the firebase URL to check for public read access.\n2. Use `/analyze_js` to find API keys and project IDs.\n3. Check for misconfigured security rules via specialized tools."
            },
            "Laravel": {
                "risk": "Medium",
                "checks": [".env", "/storage/logs/laravel.log"],
                "procedure": "1. Try accessing the `.env` file directly.\n2. Check for exposed logs in `/storage/logs/`.\n3. Look for debug mode (Ignition) which can lead to RCE."
            },
            "Git": {
                "risk": "Critical",
                "checks": ["/.git/HEAD", "/.gitignore"],
                "procedure": "1. Check if `/.git/HEAD` exists and contains 'ref: refs/heads/master'.\n2. Use `git-dumper` or similar tools to extract the full repository if exposed.\n3. Check `/.gitignore` to find names of sensitive files that might be on the server."
            }
        }
        
        # Sophisticated URL Patterns
        self.vuln_patterns = [
            {
                "name": "🎯 Potential IDOR / BOLA",
                "pattern": r'(id|uid|uuid|account|order|user|member|profile|invoice|document)_id\s*=[0-9a-f\-]+',
                "severity": "Medium",
                "impact": "Account Takeover (ATO) or Unauthorized Data Access.",
                "procedure": "1. Capture the request in Burp/Caido.\n2. Change the numeric/UUID value to another user's ID.\n3. If the response contains private data (PII) or allows modification, it's a valid IDOR."
            },
            {
                "name": "🔗 Potential SSRF",
                "pattern": r'(url|proxy|dest|destination|next|return|redirect|uri|link|path)\s*=\s*(https?|file|ftp|php|dict|gopher)',
                "severity": "High",
                "impact": "Internal network scanning, access to cloud metadata (AWS/GCP), or RCE.",
                "procedure": "1. Replace the URL with a collaborator link (e.g., Interact.sh).\n2. Try internal IPs: `http://127.0.0.1` or `http://169.254.169.254` (Cloud Metadata).\n3. Test for different protocols: `file:///etc/passwd`, `gopher://`, etc."
            },
            {
                "name": "📂 Potential LFI / Path Traversal",
                "pattern": r'(file|page|include|path|template|doc|document|view|lang|layout)\s*=\s*[a-zA-Z0-9_\-\.]+',
                "severity": "High",
                "impact": "Local code execution or sensitive information disclosure (e.g., config files).",
                "procedure": r"1. Try basic traversal: `../../../../etc/passwd` or `..\..\..\..\windows\win.ini`.\n2. Use PHP wrappers if applicable: `php://filter/read=convert.base64-encode/resource=config.php`.\n3. Try null byte injection (`%00`) or nested traversal (`....//....//`)."
            },
            {
                "name": "🖥️ Potential RCE / Command Injection",
                "pattern": r'(cmd|exec|sh|shell|run|query|search|ping|eval)\s*=\s*[a-zA-Z0-9_\-]+',
                "severity": "Critical",
                "impact": "Full system compromise and server control.",
                "procedure": "1. Try simple command execution: `;id`, `|whoami`, `` `uname -a` ``.\n2. Test for out-of-band execution: `;curl http://YOUR_COLLABORATOR`.\n3. Attempt to write a web shell if partial execution is confirmed."
            },
            {
                "name": "🐛 Debug/Admin Mode Exposed",
                "pattern": r'(debug|verbose|test|admin|devel|config|env|mode|status)\s*=\s*(true|1|yes|y|devel|admin|root)',
                "severity": "Medium",
                "impact": "Information Disclosure of system internals or Admin access.",
                "procedure": "1. Toggle values (e.g., `admin=false` -> `admin=true`).\n2. Look for stack traces, environment variables, or extra UI elements.\n3. Check for exposed routes that become visible with debug enabled (e.g., `/phpinfo`, `/_profiler`)."
            }
        ]

    def analyze_tech_stack(self, technologies: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze detected technologies with passive intelligence.
        """
        findings = []
        
        for tech in technologies:
            for vuln_tech, data in self.tech_intel.items():
                if vuln_tech.lower() in tech.lower():
                    findings.append({
                        "title": f"🛡️ Manual Review: {tech}",
                        "description": f"The technology **{tech}** was detected. Based on its nature, it requires manual verification of common misconfigurations.",
                        "severity": data['risk'],
                        "procedure": data['procedure'],
                        "impact": f"Variable (RCE, Auth Bypass, or Data Leak depending on {tech} version).",
                    })
        
        return findings

    def analyze_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze URLs for various vulnerability patterns and provide detailed manual procedures.
        """
        findings = []
        seen_patterns = set() # Avoid too many duplicate findings for the same pattern on same target
        
        for url in urls:
            for p in self.vuln_patterns:
                if re.search(p['pattern'], url, re.IGNORECASE):
                    # Create a unique key for this finding to avoid flooding
                    key = f"{p['name']}_{url.split('?')[0]}"
                    if key in seen_patterns:
                        continue
                        
                    findings.append({
                        "title": p['name'],
                        "description": f"URL appears to contain parameters susceptible to **{p['name'].split(' ')[-1]}** attacks.",
                        "severity": p['severity'],
                        "procedure": p['procedure'],
                        "impact": p['impact'],
                        "evidence": url
                    })
                    seen_patterns.add(key)
        
        return findings

    def check_git_exposure(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Simulate Git check (normally requires requests, here returning pattern logic)
        """
        return {
            "title": "Check for Git Exposure",
            "description": "Source code management files might be exposed.",
            "severity": "High",
            "suggestion": f"Try accessing `{url}/.git/HEAD` manually or use automated tools.",
            "dork": f"site:{url} inurl:.git"
        }

    def analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Analyze HTTP headers for security best practices.
        """
        missing = []
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options'
        ]
        
        for header in security_headers:
            if not any(h.lower() == header.lower() for h in headers.keys()):
                missing.append({
                    "title": f"Missing Header: {header}",
                    "description": f"The security header `{header}` is missing.",
                    "severity": "Low",
                    "suggestion": "Configure the web server to send this header."
                })
        
        return missing

    def analyze_js_files_smart(self, js_files: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze JS filenames for potential sensitivity and provide testing hints.
        """
        findings = []
        sensitive_keywords = ['admin', 'config', 'auth', 'api', 'main', 'app', 'secret', 'dev', 'internal']
        
        for js_url in js_files:
            filename = js_url.split('/')[-1].lower()
            for keyword in sensitive_keywords:
                if keyword in filename:
                    findings.append({
                        "title": f"📑 Critical JS File: {filename}",
                        "description": f"The JavaScript file `{filename}` may contain sensitive logic or hardcoded credentials.",
                        "severity": "Medium",
                        "procedure": (
                            f"1. Run `/analyze_js {js_url}` for automated secret extraction.\n"
                            f"2. Manually search for keywords like `apiKey`, `token`, `password`, `secret`, `bearer`.\n"
                            f"3. Look for unpublished API endpoints or hidden administrative routes."
                        ),
                        "impact": "Information disclosure or unauthorized API access.",
                        "evidence": js_url
                    })
                    break
        
        return findings

    def generate_ai_report(self, domain: str, scan_data: Dict[str, Any]) -> str:
        """
        Generate a strategic, conversational 'AI-style' summary.
        """
        techs = scan_data.get('technologies', [])
        vuln_list = scan_data.get('vulns', [])
        
        summary = f"🧠 **Antigravity Smart Security Assessment: {domain}**\n"
        summary += f"*(Analysis Matrix Version 2.4 | {datetime.now().strftime('%Y-%m-%d %H:%M')})*\n\n"
        
        if not techs and not vuln_list:
            summary += (
                "🕵️ I've completed a passive surface analysis of this target. The perimeter appears modern and well-hardened, "
                "with minimal information leakage. No immediate entry points were identified via traditional passive means.\n\n"
                "💡 **Next Strategic Move**: Direct your efforts toward deep JavaScript analysis and directory fuzzing in `#endpoints`."
            )
            return summary

        summary += (
            "Based on the reconnaissance data, I've mapped out the following tactical opportunities. "
            "This target has several 'soft' spots where manual intervention could yield significant findings:\n\n"
        )
        
        # Tech Analysis
        if techs:
            critical_tech = [t for t in techs if any(k in t.lower() for k in self.tech_intel.keys())]
            if critical_tech:
                summary += f"🏗️ **Infrastructure Risk**: The use of **{', '.join(critical_tech[:2])}** is interesting. These stacks are powerful but prone to misconfigurations (like exposed `.env` or `.git`).\n\n"
            else:
                summary += f"🏗️ **Tech Stack**: The target is built on **{', '.join(techs[:3])}**. This is a relatively standard stack, meaning common CVEs and misconfigs from 2023-2024 should be checked.\n\n"

        # Vulnerability Strategy
        if vuln_list:
            high_vulns = [v for v in vuln_list if v.get('severity') in ['High', 'Critical']]
            medium_vulns = [v for v in vuln_list if v.get('severity') == 'Medium']
            
            if high_vulns:
                summary += f"🔥 **Primary Attack Vectors**: I've identified **{len(high_vulns)}** high-risk patterns (SSRF/LFI/RCE). These represent the fastest path to a P1/P2 bounty. **Prioritize the URLs in `#security-findings` immediately.**\n\n"
            
            if medium_vulns:
                summary += f"🚧 **Secondary Opportunities**: There are **{len(medium_vulns)}** medium-severity findings, including potential IDORs and exposed debug flags. These are perfect for demonstrating business logic flaws.\n\n"

        summary += "🚀 **Your 3-Step Action Plan:**\n"
        
        # Dynamic Action Plan
        plan_steps = []
        if any('SSRF' in v.get('title', '') or 'LFI' in v.get('title', '') for v in vuln_list):
            plan_steps.append("1. **Verify Parameter Vulnerabilities**: Use the provided procedures for the LFI/SSRF candidates.")
        else:
            plan_steps.append("1. **Deep Directory Fuzzing**: Use a larger wordlist on endpoints found in `#endpoints`.")
            
        if any('Git' in v.get('title', '') or 'Firebase' in v.get('title', '') for v in vuln_list):
            plan_steps.append("2. **Exploit Data Exposure**: Attempt to dump the exposed Git repo or Firebase DB.")
        else:
            plan_steps.append("2. **JS Secret Hunt**: Run `/analyze_js` on the scripts found to uncover API keys.")
            
        plan_steps.append("3. **Contextual IDOR**: Log in with two accounts and test the ID-based parameters found in URL analysis.")
        
        summary += "\n".join(plan_steps)
        summary += "\n\n*Remember: This is a passive assessment. Always stay within scoped boundaries during manual testing.*"
        
        return summary
