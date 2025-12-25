"""
Cloud & Secrets Discovery Module
================================
S3 bucket enumeration, GitHub dorking, API key detection, and more.
"""

import aiohttp
import asyncio
import re
import hashlib
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, quote


class CloudSecrets:
    """Cloud resource and secrets discovery tools"""
    
    def __init__(self):
        self.session = None
        self.timeout = aiohttp.ClientTimeout(total=20)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    async def __aenter__(self):
        await self.get_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()
        
        # S3 bucket permutations
        self.bucket_permutations = [
            '{company}', '{company}-dev', '{company}-prod', '{company}-staging',
            '{company}-backup', '{company}-backups', '{company}-data', '{company}-files',
            '{company}-assets', '{company}-static', '{company}-media', '{company}-images',
            '{company}-uploads', '{company}-public', '{company}-private', '{company}-internal',
            '{company}-test', '{company}-testing', '{company}-qa', '{company}-uat',
            '{company}-logs', '{company}-logging', '{company}-archive', '{company}-old',
            '{company}-app', '{company}-application', '{company}-web', '{company}-website',
            '{company}-api', '{company}-cdn', '{company}-content', '{company}-storage',
            'dev-{company}', 'prod-{company}', 'staging-{company}', 'backup-{company}',
            '{company}bucket', '{company}-bucket', '{company}s3', '{company}-s3',
        ]
        
        # Secret patterns for detection
        self.secret_patterns = {
            # AWS
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
            'AWS ARN': r'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-zA-Z0-9-_/:.]+',
            
            # Google
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'Google Cloud Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            
            # GitHub
            'GitHub Token': r'gh[ps]_[0-9A-Za-z]{36}',
            'GitHub OAuth': r'gho_[0-9A-Za-z]{36}',
            'GitHub App Token': r'ghu_[0-9A-Za-z]{36}',
            'GitHub Refresh Token': r'ghr_[0-9A-Za-z]{36}',
            
            # Slack
            'Slack Token': r'xox[baprs]-[0-9A-Za-z]{10,48}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            
            # Stripe
            'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
            'Stripe Publishable': r'pk_live_[0-9a-zA-Z]{24}',
            
            # Twilio
            'Twilio API Key': r'SK[0-9a-fA-F]{32}',
            'Twilio Account SID': r'AC[a-zA-Z0-9_\-]{32}',
            
            # Mailgun
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            
            # Heroku
            'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            
            # DigitalOcean
            'DigitalOcean Token': r'dop_v1_[0-9a-f]{64}',
            
            # npm
            'NPM Token': r'npm_[0-9A-Za-z]{36}',
            
            # PyPI
            'PyPI Token': r'pypi-[0-9A-Za-z_-]{64,}',
            
            # Discord
            'Discord Token': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
            'Discord Webhook': r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
            
            # Generic patterns
            'Private Key': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'JWT Token': r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*',
            'Bearer Token': r'[Bb]earer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*',
            'Basic Auth': r'[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}',
            'Password in URL': r'[a-zA-Z]{3,10}://[^/\\s:@]+:[^/\\s:@]+@[^/\\s:@]+',
            'Generic API Key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{20,}["\']?',
            'Generic Secret': r'["\']?secret["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{16,}["\']?',
            'Generic Token': r'["\']?token["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{20,}["\']?',
            'Generic Password': r'["\']?password["\']?\s*[:=]\s*["\']?[^"\']{8,}["\']?',
        }
        
        # GitHub dork queries
        self.github_dorks = [
            'filename:.env {keyword}',
            'filename:config.php {keyword}',
            'filename:configuration.php {keyword}',
            'filename:settings.py {keyword}',
            'filename:.htpasswd {keyword}',
            'filename:id_rsa {keyword}',
            'filename:id_dsa {keyword}',
            'filename:.bash_history {keyword}',
            'filename:credentials {keyword}',
            'filename:secrets {keyword}',
            'filename:wp-config.php {keyword}',
            'password {keyword}',
            'api_key {keyword}',
            'apikey {keyword}',
            'secret_key {keyword}',
            'aws_secret {keyword}',
            'aws_access_key_id {keyword}',
            'AKIA {keyword}',
            'Bearer {keyword}',
        ]
    
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
    
    # ==========================================
    # S3 BUCKET ENUMERATION
    # ==========================================
    
    async def enumerate_s3_buckets(self, company: str) -> Dict[str, Any]:
        """
        Enumerate potential S3 buckets for a company/domain
        """
        results = {
            "company": company,
            "found_buckets": [],
            "public_buckets": [],
            "private_buckets": [],
            "not_found": [],
            "total_checked": 0
        }
        
        session = await self.get_session()
        
        # Generate bucket names
        bucket_names = []
        company_clean = company.replace('.', '-').replace('_', '-').lower()
        company_nodot = company.replace('.', '').replace('-', '').replace('_', '').lower()
        
        for perm in self.bucket_permutations:
            bucket_names.append(perm.format(company=company_clean))
            bucket_names.append(perm.format(company=company_nodot))
        
        # Remove duplicates
        bucket_names = list(set(bucket_names))
        
        async def check_bucket(bucket_name: str) -> Optional[Dict]:
            # Check different regions
            regions = ['', 's3.us-east-1', 's3.us-west-2', 's3.eu-west-1', 's3.ap-southeast-1']
            
            for region in regions:
                if region:
                    url = f"https://{bucket_name}.{region}.amazonaws.com"
                else:
                    url = f"https://{bucket_name}.s3.amazonaws.com"
                
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        result = {
                            "name": bucket_name,
                            "url": url,
                            "status": resp.status,
                            "public": False
                        }
                        
                        if resp.status == 200:
                            result["public"] = True
                            body = await resp.text()
                            if '<ListBucketResult' in body:
                                result["listing_enabled"] = True
                            return result
                        elif resp.status == 403:
                            # Bucket exists but no access
                            result["public"] = False
                            return result
                        elif resp.status == 404:
                            continue  # Try next region
                            
                except:
                    continue
            
            return None
        
        # Check buckets in batches
        batch_size = 10
        for i in range(0, len(bucket_names), batch_size):
            batch = bucket_names[i:i + batch_size]
            tasks = [check_bucket(name) for name in batch]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                results["total_checked"] += 1
                if response and not isinstance(response, Exception):
                    results["found_buckets"].append(response)
                    if response.get("public"):
                        results["public_buckets"].append(response)
                    else:
                        results["private_buckets"].append(response)
        
        return results
    
    # ==========================================
    # AZURE BLOB ENUMERATION
    # ==========================================
    
    async def enumerate_azure_blobs(self, company: str) -> Dict[str, Any]:
        """
        Enumerate potential Azure blob storage containers
        """
        results = {
            "company": company,
            "found_containers": [],
            "public_containers": [],
            "total_checked": 0
        }
        
        session = await self.get_session()
        company_clean = company.replace('.', '').replace('-', '').replace('_', '').lower()
        
        container_names = ['files', 'data', 'backup', 'backups', 'public', 'private', 
                         'assets', 'static', 'images', 'uploads', 'media', 'content',
                         'documents', 'docs', 'archive', 'logs']
        
        storage_accounts = [
            f"{company_clean}",
            f"{company_clean}storage",
            f"{company_clean}blob",
            f"{company_clean}data",
            f"storage{company_clean}",
        ]
        
        async def check_container(account: str, container: str) -> Optional[Dict]:
            url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        return {
                            "account": account,
                            "container": container,
                            "url": f"https://{account}.blob.core.windows.net/{container}",
                            "public": True
                        }
                    elif resp.status == 404:
                        return None
            except:
                pass
            return None
        
        tasks = []
        for account in storage_accounts:
            for container in container_names:
                tasks.append(check_container(account, container))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            results["total_checked"] += 1
            if response and not isinstance(response, Exception):
                results["found_containers"].append(response)
                results["public_containers"].append(response)
        
        return results
    
    # ==========================================
    # GCP BUCKET ENUMERATION
    # ==========================================
    
    async def enumerate_gcp_buckets(self, company: str) -> Dict[str, Any]:
        """
        Enumerate potential GCP storage buckets
        """
        results = {
            "company": company,
            "found_buckets": [],
            "public_buckets": [],
            "total_checked": 0
        }
        
        session = await self.get_session()
        company_clean = company.replace('.', '-').replace('_', '-').lower()
        
        bucket_names = [
            f"{company_clean}", f"{company_clean}-backup", f"{company_clean}-data",
            f"{company_clean}-storage", f"{company_clean}-public", f"{company_clean}-private",
            f"{company_clean}-prod", f"{company_clean}-dev", f"{company_clean}-staging"
        ]
        
        async def check_bucket(bucket_name: str) -> Optional[Dict]:
            url = f"https://storage.googleapis.com/{bucket_name}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        return {
                            "name": bucket_name,
                            "url": url,
                            "public": True
                        }
                    elif resp.status == 403:
                        return {
                            "name": bucket_name,
                            "url": url,
                            "public": False,
                            "exists": True
                        }
            except:
                pass
            return None
        
        tasks = [check_bucket(name) for name in bucket_names]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            results["total_checked"] += 1
            if response and not isinstance(response, Exception):
                results["found_buckets"].append(response)
                if response.get("public"):
                    results["public_buckets"].append(response)
        
        return results
    
    # ==========================================
    # SECRET DETECTION IN CONTENT
    # ==========================================
    
    async def scan_for_secrets(self, url: str) -> Dict[str, Any]:
        """
        Scan a URL/page for exposed secrets and credentials
        """
        results = {
            "url": url,
            "secrets_found": [],
            "total_patterns_checked": len(self.secret_patterns),
            "risk_level": "low"
        }
        
        session = await self.get_session()
        
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    
                    for secret_type, pattern in self.secret_patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches[:5]:  # Limit matches per type
                            # Mask the secret for safety
                            if len(str(match)) > 10:
                                masked = str(match)[:8] + "..." + str(match)[-4:]
                            else:
                                masked = str(match)[:4] + "..."
                            
                            results["secrets_found"].append({
                                "type": secret_type,
                                "value": masked,
                                "full_length": len(str(match))
                            })
                    
                    # Determine risk level
                    if len(results["secrets_found"]) > 5:
                        results["risk_level"] = "critical"
                    elif len(results["secrets_found"]) > 2:
                        results["risk_level"] = "high"
                    elif len(results["secrets_found"]) > 0:
                        results["risk_level"] = "medium"
                        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # GITHUB DORK GENERATION
    # ==========================================
    
    def generate_github_dorks(self, keyword: str) -> Dict[str, Any]:
        """
        Generate GitHub dork queries for a target
        """
        results = {
            "keyword": keyword,
            "dorks": [],
            "total": 0
        }
        
        for dork in self.github_dorks:
            query = dork.format(keyword=keyword)
            encoded = quote(query)
            results["dorks"].append({
                "query": query,
                "url": f"https://github.com/search?q={encoded}&type=code"
            })
        
        # Add organization-specific dorks
        org_dorks = [
            f'org:{keyword} password',
            f'org:{keyword} api_key',
            f'org:{keyword} secret',
            f'org:{keyword} token',
            f'org:{keyword} credential',
            f'org:{keyword} filename:.env',
            f'org:{keyword} filename:config',
        ]
        
        for dork in org_dorks:
            encoded = quote(dork)
            results["dorks"].append({
                "query": dork,
                "url": f"https://github.com/search?q={encoded}&type=code"
            })
        
        results["total"] = len(results["dorks"])
        
        return results
    
    # ==========================================
    # GOOGLE DORK GENERATION
    # ==========================================
    
    def generate_google_dorks(self, domain: str) -> Dict[str, Any]:
        """
        Generate Google dork queries for a target domain
        """
        dorks = [
            # File discovery
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:doc OR filetype:docx',
            f'site:{domain} filetype:xls OR filetype:xlsx',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:bak',
            f'site:{domain} filetype:conf OR filetype:config',
            f'site:{domain} filetype:env',
            
            # Sensitive directories
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:backup',
            f'site:{domain} inurl:config',
            f'site:{domain} inurl:api',
            f'site:{domain} inurl:internal',
            f'site:{domain} inurl:private',
            f'site:{domain} inurl:dev OR inurl:staging',
            
            # Sensitive content
            f'site:{domain} "password"',
            f'site:{domain} "api_key"',
            f'site:{domain} "secret"',
            f'site:{domain} "token"',
            f'site:{domain} "credentials"',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} intitle:"directory listing"',
            
            # Error pages
            f'site:{domain} "error" OR "exception"',
            f'site:{domain} "sql syntax"',
            f'site:{domain} "fatal error"',
            f'site:{domain} "stack trace"',
            
            # Technology specific
            f'site:{domain} inurl:wp-content',
            f'site:{domain} inurl:wp-admin',
            f'site:{domain} ext:php inurl:?',
            f'site:{domain} inurl:phpmyadmin',
            
            # Exposed data
            f'site:{domain} "email" filetype:csv',
            f'site:{domain} "username" filetype:txt',
            f'site:{domain} "database" OR "mysql"',
        ]
        
        results = {
            "domain": domain,
            "dorks": [],
            "total": len(dorks)
        }
        
        for dork in dorks:
            encoded = quote(dork)
            results["dorks"].append({
                "query": dork,
                "url": f"https://www.google.com/search?q={encoded}"
            })
        
        return results
    
    # ==========================================
    # EMAIL HARVESTING
    # ==========================================
    
    async def harvest_emails(self, domain: str) -> Dict[str, Any]:
        """
        Harvest email addresses related to a domain
        """
        results = {
            "domain": domain,
            "emails": [],
            "sources": []
        }
        
        session = await self.get_session()
        
        # Try to get from the website itself
        try:
            url = f"https://{domain}" if not domain.startswith('http') else domain
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    # Email regex
                    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    emails = re.findall(email_pattern, content)
                    for email in set(emails):
                        if domain.split('.')[-2] in email.lower():  # Related to domain
                            results["emails"].append(email)
                            results["sources"].append({"email": email, "source": url})
        except:
            pass
        
        # Common email patterns to suggest
        common_patterns = [
            f"info@{domain}",
            f"contact@{domain}",
            f"support@{domain}",
            f"admin@{domain}",
            f"sales@{domain}",
            f"hr@{domain}",
            f"careers@{domain}",
            f"security@{domain}",
            f"webmaster@{domain}",
        ]
        
        results["common_patterns"] = common_patterns
        results["emails"] = list(set(results["emails"]))
        
        return results
    
    # ==========================================
    # SUBDOMAIN FROM CERTIFICATE TRANSPARENCY
    # ==========================================
    
    async def crt_sh_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Get subdomains from Certificate Transparency logs (crt.sh)
        """
        results = {
            "domain": domain,
            "subdomains": [],
            "certificates": 0
        }
        
        session = await self.get_session()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results["certificates"] = len(data)
                    
                    subdomains = set()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub and '*' not in sub and sub.endswith(domain):
                                subdomains.add(sub)
                    
                    results["subdomains"] = sorted(list(subdomains))
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # SHODAN DORK GENERATION
    # ==========================================
    
    def generate_shodan_dorks(self, target: str) -> Dict[str, Any]:
        """
        Generate Shodan dork queries for a target
        """
        dorks = [
            # Basic searches
            f'hostname:{target}',
            f'ssl.cert.subject.cn:{target}',
            f'org:"{target}"',
            
            # Exposed services
            f'hostname:{target} port:22',
            f'hostname:{target} port:3389',
            f'hostname:{target} port:21',
            f'hostname:{target} port:23',
            f'hostname:{target} port:3306',
            f'hostname:{target} port:5432',
            f'hostname:{target} port:27017',
            f'hostname:{target} port:6379',
            f'hostname:{target} port:11211',
            f'hostname:{target} port:9200',
            
            # Web services
            f'hostname:{target} http.title:"Dashboard"',
            f'hostname:{target} http.title:"Admin"',
            f'hostname:{target} http.title:"Login"',
            f'hostname:{target} "jenkins"',
            f'hostname:{target} "gitlab"',
            f'hostname:{target} "grafana"',
            f'hostname:{target} "kibana"',
            
            # Vulnerabilities
            f'hostname:{target} vuln:CVE-2021-44228',  # Log4j
            f'hostname:{target} vuln:CVE-2021-26855',  # Exchange
            
            # Technologies
            f'hostname:{target} product:"nginx"',
            f'hostname:{target} product:"Apache"',
            f'hostname:{target} product:"IIS"',
        ]
        
        results = {
            "target": target,
            "dorks": [],
            "total": len(dorks)
        }
        
        for dork in dorks:
            results["dorks"].append({
                "query": dork,
                "url": f"https://www.shodan.io/search?query={quote(dork)}"
            })
        
        return results
    
    # ==========================================
    # FIREBASE MISCONFIGURATION CHECK
    # ==========================================
    
    async def check_firebase(self, app_name: str) -> Dict[str, Any]:
        """
        Check for Firebase database misconfigurations
        """
        results = {
            "app_name": app_name,
            "vulnerable": False,
            "exposed_endpoints": [],
            "checked": []
        }
        
        session = await self.get_session()
        
        # Firebase database URLs
        urls = [
            f"https://{app_name}.firebaseio.com/.json",
            f"https://{app_name}-default-rtdb.firebaseio.com/.json",
        ]
        
        for url in urls:
            results["checked"].append(url)
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if content != 'null' and len(content) > 10:
                            results["vulnerable"] = True
                            results["exposed_endpoints"].append({
                                "url": url,
                                "status": resp.status,
                                "sample": content[:200] + "..." if len(content) > 200 else content
                            })
            except:
                continue
        
        return results
