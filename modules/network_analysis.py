"""
SSL/TLS & Network Analysis Module
=================================
SSL certificate analysis, ASN lookup, CIDR enumeration, and network tools.
"""

import aiohttp
import asyncio
import socket
import ssl
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse


class NetworkAnalysis:
    """SSL/TLS and network analysis tools"""
    
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
    # SSL/TLS CERTIFICATE ANALYSIS
    # ==========================================
    
    async def analyze_ssl_certificate(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Comprehensive SSL/TLS certificate analysis
        """
        results = {
            "domain": domain,
            "port": port,
            "ssl_enabled": False,
            "certificate": {},
            "chain": [],
            "vulnerabilities": [],
            "warnings": [],
            "grade": "Unknown"
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            loop = asyncio.get_event_loop()
            
            def get_cert():
                conn = context.wrap_socket(
                    socket.socket(socket.AF_INET),
                    server_hostname=domain
                )
                conn.settimeout(10)
                conn.connect((domain, port))
                cert = conn.getpeercert(binary_form=True)
                cert_dict = conn.getpeercert()
                cipher = conn.cipher()
                version = conn.version()
                conn.close()
                return cert, cert_dict, cipher, version
            
            cert_binary, cert_dict, cipher, tls_version = await loop.run_in_executor(None, get_cert)
            
            results["ssl_enabled"] = True
            results["tls_version"] = tls_version
            results["cipher"] = {
                "name": cipher[0] if cipher else "Unknown",
                "version": cipher[1] if cipher else "Unknown",
                "bits": cipher[2] if cipher else 0
            }
            
            if cert_dict:
                # Parse certificate info
                results["certificate"] = {
                    "subject": dict(x[0] for x in cert_dict.get('subject', [])),
                    "issuer": dict(x[0] for x in cert_dict.get('issuer', [])),
                    "version": cert_dict.get('version'),
                    "serial_number": cert_dict.get('serialNumber'),
                    "not_before": cert_dict.get('notBefore'),
                    "not_after": cert_dict.get('notAfter'),
                    "subject_alt_names": []
                }
                
                # Get SANs
                for san_type, san_value in cert_dict.get('subjectAltName', []):
                    results["certificate"]["subject_alt_names"].append(f"{san_type}:{san_value}")
                
                # Check expiration
                if cert_dict.get('notAfter'):
                    try:
                        # Parse the date
                        expiry_str = cert_dict['notAfter']
                        # Format: 'Dec 31 23:59:59 2024 GMT'
                        expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry - datetime.now()).days
                        
                        results["certificate"]["days_until_expiry"] = days_until_expiry
                        
                        if days_until_expiry < 0:
                            results["vulnerabilities"].append("Certificate has EXPIRED!")
                        elif days_until_expiry < 30:
                            results["warnings"].append(f"Certificate expires in {days_until_expiry} days")
                        elif days_until_expiry < 90:
                            results["warnings"].append(f"Certificate expires in {days_until_expiry} days")
                    except:
                        pass
            
            # Check TLS version vulnerabilities
            if tls_version:
                if 'SSLv2' in tls_version or 'SSLv3' in tls_version:
                    results["vulnerabilities"].append(f"Insecure protocol: {tls_version}")
                elif 'TLSv1.0' in tls_version:
                    results["warnings"].append("TLS 1.0 is deprecated")
                elif 'TLSv1.1' in tls_version:
                    results["warnings"].append("TLS 1.1 is deprecated")
            
            # Check cipher strength
            if cipher and cipher[2]:
                bits = cipher[2]
                if bits < 128:
                    results["vulnerabilities"].append(f"Weak cipher: {bits} bits")
                elif bits < 256:
                    results["warnings"].append(f"Consider stronger cipher: {bits} bits")
            
            # Calculate grade
            vuln_count = len(results["vulnerabilities"])
            warn_count = len(results["warnings"])
            
            if vuln_count > 0:
                results["grade"] = "F"
            elif warn_count > 2:
                results["grade"] = "C"
            elif warn_count > 0:
                results["grade"] = "B"
            else:
                results["grade"] = "A"
                
        except ssl.SSLError as e:
            results["error"] = f"SSL Error: {str(e)}"
            results["vulnerabilities"].append(str(e))
        except socket.error as e:
            results["error"] = f"Connection Error: {str(e)}"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # CHECK FOR WEAK SSL/TLS CONFIGS
    # ==========================================
    
    async def check_ssl_vulnerabilities(self, domain: str) -> Dict[str, Any]:
        """
        Check for common SSL/TLS vulnerabilities
        """
        results = {
            "domain": domain,
            "vulnerabilities": [],
            "supported_protocols": [],
            "weak_ciphers": [],
            "issues": []
        }
        
        # Protocols to test
        protocols = [
            ('SSLv2', ssl.PROTOCOL_SSLv23),
            ('SSLv3', ssl.PROTOCOL_SSLv23),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
        ]
        
        loop = asyncio.get_event_loop()
        
        async def test_protocol(proto_name: str, proto_version) -> Optional[str]:
            if proto_version is None:
                return None
            try:
                def connect():
                    context = ssl.SSLContext(proto_version)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    wrapped = context.wrap_socket(sock, server_hostname=domain)
                    wrapped.connect((domain, 443))
                    version = wrapped.version()
                    wrapped.close()
                    return version
                
                version = await loop.run_in_executor(None, connect)
                if version:
                    return version
            except:
                pass
            return None
        
        # Test each protocol
        for proto_name, proto_version in protocols:
            version = await test_protocol(proto_name, proto_version)
            if version:
                results["supported_protocols"].append(version)
                if 'SSL' in version or version in ['TLSv1.0', 'TLSv1.1']:
                    results["vulnerabilities"].append(f"Deprecated protocol supported: {version}")
        
        # Additional checks
        if not results["supported_protocols"]:
            results["issues"].append("Could not determine supported protocols")
        elif 'TLSv1.2' not in str(results["supported_protocols"]) and 'TLSv1.3' not in str(results["supported_protocols"]):
            results["issues"].append("Modern TLS (1.2/1.3) not detected")
        
        return results
    
    # ==========================================
    # ASN LOOKUP
    # ==========================================
    
    async def asn_lookup(self, target: str) -> Dict[str, Any]:
        """
        Look up ASN information for a domain or IP
        """
        results = {
            "target": target,
            "ip": None,
            "asn": None,
            "asn_name": None,
            "asn_country": None,
            "asn_range": None,
            "related_ranges": []
        }
        
        session = await self.get_session()
        
        # Resolve domain to IP if needed
        try:
            if not target.replace('.', '').isdigit():
                ip = socket.gethostbyname(target)
                results["ip"] = ip
            else:
                ip = target
                results["ip"] = ip
        except:
            results["error"] = "Could not resolve IP"
            return results
        
        # Query ASN info from multiple sources
        apis = [
            f"https://ipapi.co/{ip}/json/",
            f"https://ipinfo.io/{ip}/json",
        ]
        
        for api_url in apis:
            try:
                async with session.get(api_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        # ipapi.co format
                        if 'asn' in data:
                            results["asn"] = data.get('asn')
                            results["asn_name"] = data.get('org', data.get('asn_org'))
                            results["asn_country"] = data.get('country')
                        
                        # ipinfo.io format
                        if 'org' in data and results["asn"] is None:
                            org = data.get('org', '')
                            if ' ' in org:
                                results["asn"] = org.split(' ')[0]
                                results["asn_name"] = ' '.join(org.split(' ')[1:])
                            results["asn_country"] = data.get('country')
                        
                        if results["asn"]:
                            break
            except:
                continue
        
        # Get IP ranges for ASN
        if results["asn"]:
            try:
                asn_num = results["asn"].replace('AS', '')
                async with session.get(f"https://api.hackertarget.com/aslookup/?q=AS{asn_num}") as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        ranges = [line.strip() for line in text.split('\n') if '/' in line]
                        results["related_ranges"] = ranges[:20]  # Limit
            except:
                pass
        
        return results
    
    # ==========================================
    # IP RANGE / CIDR ENUMERATION
    # ==========================================
    
    async def enumerate_cidr(self, cidr: str, sample_size: int = 10) -> Dict[str, Any]:
        """
        Enumerate IPs in a CIDR range and check for live hosts
        """
        import ipaddress
        
        results = {
            "cidr": cidr,
            "total_ips": 0,
            "live_hosts": [],
            "sample_size": sample_size
        }
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            results["total_ips"] = network.num_addresses
            
            # Get sample of IPs to check
            ips_to_check = []
            for i, ip in enumerate(network.hosts()):
                if i >= sample_size:
                    break
                ips_to_check.append(str(ip))
            
            session = await self.get_session()
            
            async def check_ip(ip: str) -> Optional[Dict]:
                try:
                    # Try HTTP
                    async with session.get(f"http://{ip}", timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        return {
                            "ip": ip,
                            "status": resp.status,
                            "server": resp.headers.get('Server', 'Unknown')
                        }
                except:
                    pass
                
                # Try HTTPS
                try:
                    async with session.get(f"https://{ip}", timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        return {
                            "ip": ip,
                            "status": resp.status,
                            "server": resp.headers.get('Server', 'Unknown'),
                            "https": True
                        }
                except:
                    pass
                
                return None
            
            tasks = [check_ip(ip) for ip in ips_to_check]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for response in responses:
                if response and not isinstance(response, Exception):
                    results["live_hosts"].append(response)
                    
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # REVERSE DNS LOOKUP
    # ==========================================
    
    async def reverse_dns(self, ip: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup
        """
        results = {
            "ip": ip,
            "hostnames": [],
            "ptr_record": None
        }
        
        try:
            loop = asyncio.get_event_loop()
            hostname, _, _ = await loop.run_in_executor(
                None, 
                socket.gethostbyaddr, 
                ip
            )
            results["ptr_record"] = hostname
            results["hostnames"].append(hostname)
        except socket.herror:
            results["error"] = "No PTR record found"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # TRACEROUTE (SIMPLIFIED)
    # ==========================================
    
    async def trace_route(self, target: str, max_hops: int = 15) -> Dict[str, Any]:
        """
        Simplified traceroute using HTTP
        """
        results = {
            "target": target,
            "resolved_ip": None,
            "hops": [],
            "destination_reached": False
        }
        
        try:
            ip = socket.gethostbyname(target)
            results["resolved_ip"] = ip
        except:
            results["error"] = "Could not resolve target"
            return results
        
        # Note: Full traceroute requires raw sockets/admin privileges
        # This is a simplified version that just checks connectivity
        
        session = await self.get_session()
        
        try:
            url = f"https://{target}" if not target.startswith('http') else target
            start_time = asyncio.get_event_loop().time()
            
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                end_time = asyncio.get_event_loop().time()
                
                results["destination_reached"] = True
                results["response_time_ms"] = round((end_time - start_time) * 1000, 2)
                results["final_status"] = resp.status
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # PING CHECK
    # ==========================================
    
    async def check_host_alive(self, targets: List[str]) -> Dict[str, Any]:
        """
        Check if hosts are alive via HTTP(S)
        """
        results = {
            "alive": [],
            "dead": [],
            "total": len(targets)
        }
        
        session = await self.get_session()
        
        async def check_target(target: str) -> Dict:
            result = {
                "target": target,
                "alive": False,
                "response_time": None,
                "status": None
            }
            
            for protocol in ['https://', 'http://']:
                url = f"{protocol}{target}" if not target.startswith('http') else target
                try:
                    start = asyncio.get_event_loop().time()
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        end = asyncio.get_event_loop().time()
                        result["alive"] = True
                        result["response_time"] = round((end - start) * 1000, 2)
                        result["status"] = resp.status
                        return result
                except:
                    continue
            
            return result
        
        tasks = [check_target(t) for t in targets]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            if isinstance(response, Exception):
                continue
            if response["alive"]:
                results["alive"].append(response)
            else:
                results["dead"].append(response["target"])
        
        return results
    
    # ==========================================
    # CDN DETECTION
    # ==========================================
    
    async def detect_cdn(self, domain: str) -> Dict[str, Any]:
        """
        Detect if domain is behind a CDN
        """
        results = {
            "domain": domain,
            "cdn_detected": False,
            "cdn_name": None,
            "indicators": [],
            "ips": []
        }
        
        session = await self.get_session()
        
        cdn_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'cf-cache-status'],
            'AWS CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop', 'cloudfront'],
            'Akamai': ['akamai', 'x-akamai', 'akamaighost'],
            'Fastly': ['x-fastly', 'fastly', 'x-served-by'],
            'MaxCDN/StackPath': ['x-cdn', 'stackpath', 'netdna'],
            'KeyCDN': ['keycdn', 'x-edge-location'],
            'Sucuri': ['x-sucuri', 'sucuri'],
            'Incapsula': ['incap_ses', 'visid_incap', 'incapsula'],
            'Azure CDN': ['x-azure', 'azure'],
            'Google Cloud CDN': ['x-goog', 'google'],
            'Varnish': ['x-varnish', 'via: varnish'],
        }
        
        try:
            # Get multiple IPs (CDNs often have multiple)
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                results["ips"] = ips
                if len(ips) > 1:
                    results["indicators"].append(f"Multiple IPs detected: {len(ips)}")
            except:
                pass
            
            # Check HTTP headers
            url = f"https://{domain}" if not domain.startswith('http') else domain
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                headers = dict(resp.headers)
                headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
                
                for cdn_name, signatures in cdn_signatures.items():
                    for sig in signatures:
                        sig_lower = sig.lower()
                        # Check header names and values
                        for hk, hv in headers_lower.items():
                            if sig_lower in hk or sig_lower in hv:
                                results["cdn_detected"] = True
                                results["cdn_name"] = cdn_name
                                results["indicators"].append(f"Header match: {sig}")
                                break
                    if results["cdn_detected"]:
                        break
                        
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # DNS ZONE TRANSFER CHECK
    # ==========================================
    
    async def check_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """
        Check if DNS zone transfer is enabled (AXFR)
        """
        import dns.resolver
        import dns.zone
        import dns.query
        
        results = {
            "domain": domain,
            "vulnerable": False,
            "nameservers": [],
            "records": []
        }
        
        try:
            # Get nameservers
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            ns_records = resolver.resolve(domain, 'NS')
            results["nameservers"] = [str(ns) for ns in ns_records]
            
            # Try zone transfer on each nameserver
            for ns in results["nameservers"]:
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns.rstrip('.'), domain, timeout=5)
                    )
                    
                    if zone:
                        results["vulnerable"] = True
                        results["vulnerable_ns"] = ns
                        
                        # Get records
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                for rdata in rdataset:
                                    results["records"].append({
                                        "name": str(name),
                                        "type": dns.rdatatype.to_text(rdataset.rdtype),
                                        "value": str(rdata)
                                    })
                        break
                except Exception:
                    continue
                    
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    # ==========================================
    # WHOIS ENHANCED
    # ==========================================
    
    async def enhanced_whois(self, domain: str) -> Dict[str, Any]:
        """
        Enhanced WHOIS lookup with additional info
        """
        results = {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "nameservers": [],
            "registrant": {},
            "raw": None
        }
        
        session = await self.get_session()
        
        try:
            # Use WHOIS API
            async with session.get(f"https://api.hackertarget.com/whois/?q={domain}") as resp:
                if resp.status == 200:
                    text = await resp.text()
                    results["raw"] = text[:3000]
                    
                    # Parse common fields
                    lines = text.split('\n')
                    for line in lines:
                        line_lower = line.lower()
                        
                        if 'registrar:' in line_lower:
                            results["registrar"] = line.split(':', 1)[1].strip()
                        elif 'creation date:' in line_lower or 'created:' in line_lower:
                            results["creation_date"] = line.split(':', 1)[1].strip()
                        elif 'expir' in line_lower and 'date' in line_lower:
                            results["expiration_date"] = line.split(':', 1)[1].strip()
                        elif 'name server:' in line_lower or 'nameserver:' in line_lower:
                            ns = line.split(':', 1)[1].strip()
                            if ns:
                                results["nameservers"].append(ns)
                                
        except Exception as e:
            results["error"] = str(e)
        
        return results
