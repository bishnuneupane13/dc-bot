"""
Scope Management Module
=======================
Automatically creates Discord categories and channels for each target domain.
Organizes all findings in structured channels.
"""

import discord
import json
import os
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict


@dataclass
class TargetScope:
    """Represents a target domain in scope"""
    domain: str
    category_id: int
    channels: Dict[str, int]  # channel_name -> channel_id
    added_at: str
    added_by: int
    status: str = "active"  # active, paused, completed
    js_files: List[str] = None # List of discovered JS URLs

    def __post_init__(self):
        if self.js_files is None:
            self.js_files = []


class ScopeManager:
    """
    Manages bug bounty program scopes with automatic channel creation.
    
    When a domain is added to scope:
    1. Creates a category named after the domain
    2. Creates organized channels for different finding types
    3. Stores scope data for persistence
    """
    
    # Channel structure for each target
    CHANNEL_STRUCTURE = {
        # Core Asset Channels
        "subdomains": {"emoji": "🌐", "topic": "All discovered subdomains"},
        "live-domains": {"emoji": "✅", "topic": "Live/active domains and ports"},
        "endpoints": {"emoji": "🔗", "topic": "Endpoints, Parameters, and JS Files"},
        
        # Findings & Security
        "security-findings": {"emoji": "🛡️", "topic": "Vulnerabilities, Secrets, Misconfigs, and Cloud Assets"},
        "technologies": {"emoji": "🔧", "topic": "Detected technologies and stack"},
        
        # Analysis & Evidence
        "screenshots": {"emoji": "📸", "topic": "Automated screenshots of targets"},
        "notes": {"emoji": "📋", "topic": "Manual notes and observations"},
        
        # Reports
        "reports": {"emoji": "📊", "topic": "Final reports and exports"},
    }
    
    def __init__(self, data_file: str = "scope_data.json"):
        self.data_file = data_file
        self.scopes: Dict[str, TargetScope] = {}
        self.guild_scopes: Dict[int, List[str]] = {}  # guild_id -> [domains]
        self.load_data()
    
    def load_data(self):
        """Load scope data from file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    for domain, scope_data in data.get('scopes', {}).items():
                        self.scopes[domain] = TargetScope(**scope_data)
                    self.guild_scopes = data.get('guild_scopes', {})
                    # Convert string keys back to int
                    self.guild_scopes = {int(k): v for k, v in self.guild_scopes.items()}
            except Exception as e:
                print(f"Error loading scope data: {e}")
    
    def save_data(self):
        """Save scope data to file"""
        try:
            data = {
                'scopes': {domain: asdict(scope) for domain, scope in self.scopes.items()},
                'guild_scopes': self.guild_scopes
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving scope data: {e}")

    def add_js_files(self, domain_or_scope: str, urls: List[str]):
        """Add discovered JS files to target scope"""
        domain = self.normalize_domain(domain_or_scope)
        # Check if already in scopes
        if domain in self.scopes:
            current = set(self.scopes[domain].js_files)
            for url in urls:
                if url.endswith('.js') or '.js?' in url:
                    current.add(url)
            # Keep a reasonable limit (latest 100)
            self.scopes[domain].js_files = sorted(list(current))[-100:]
            self.save_data()

    def get_js_files(self, guild_id: int, domain: str = None) -> List[str]:
        """Get discovered JS files for a domain or whole guild"""
        files = []
        if domain:
            domain = self.normalize_domain(domain)
            if domain in self.scopes:
                return self.scopes[domain].js_files
        else:
            # Search all domains in guild
            domains = self.guild_scopes.get(guild_id, [])
            for d in domains:
                if d in self.scopes:
                    files.extend(self.scopes[d].js_files)
        
        # Return unique, sorted, limited list
        return sorted(list(set(files)))[:25]
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain string (remove protocol, paths, etc)"""
        if not domain:
            return ""
        clean = domain.lower().strip()
        clean = clean.replace('https://', '').replace('http://', '')
        clean = clean.split('/')[0]  # Remove paths
        clean = clean.split('?')[0]  # Remove queries
        return clean

    async def add_target(self, guild: discord.Guild, domain: str, 
                         added_by: discord.Member) -> Dict[str, Any]:
        """
        Add a new target domain to scope.
        Creates category and all channels.
        
        Args:
            guild: Discord guild
            domain: Target domain
            added_by: Member who added the target
            
        Returns:
            Dict with created category and channels info
        """
        # Clean domain name
        domain_clean = self.normalize_domain(domain)
        
        # Check if already exists
        scope_key = f"{guild.id}_{domain_clean}"
        if scope_key in self.scopes:
            return {
                "success": False,
                "error": f"Domain `{domain_clean}` is already in scope!",
                "existing": True
            }
        
        try:
            # Create category
            category_name = f"🎯 {domain_clean}"
            category = await guild.create_category(
                name=category_name,
                reason=f"Bug Bounty scope added by {added_by.name}"
            )
            
            # Create channels
            channels = {}
            for channel_name, config in self.CHANNEL_STRUCTURE.items():
                channel = await category.create_text_channel(
                    name=f"{config['emoji']}-{channel_name}",
                    topic=f"{config['topic']} for {domain_clean}",
                    reason=f"Auto-created for scope: {domain_clean}"
                )
                channels[channel_name] = channel.id
                
                # Send welcome message to channel
                embed = discord.Embed(
                    title=f"{config['emoji']} {channel_name.replace('-', ' ').title()}",
                    description=config['topic'],
                    color=discord.Color.blue()
                )
                embed.add_field(name="Target", value=f"`{domain_clean}`", inline=True)
                embed.set_footer(text=f"Created by {added_by.name}")
                await channel.send(embed=embed)
                # Note: We are keeping the initial message simpler as requested, 
                # but 'interactive states' will be handled by the bot command to avoid circular deps.
            
            # Store scope data
            scope = TargetScope(
                domain=domain_clean,
                category_id=category.id,
                channels=channels,
                added_at=datetime.now().isoformat(),
                added_by=added_by.id,
                status="active"
            )
            self.scopes[scope_key] = scope
            
            # Track by guild
            if guild.id not in self.guild_scopes:
                self.guild_scopes[guild.id] = []
            self.guild_scopes[guild.id].append(domain_clean)
            
            self.save_data()
            
            return {
                "success": True,
                "domain": domain_clean,
                "category_id": category.id,
                "category_name": category_name,
                "channels_created": len(channels),
                "channels": channels
            }
            
        except discord.Forbidden:
            return {
                "success": False,
                "error": "Bot lacks permissions to create categories/channels!"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def remove_target(self, guild: discord.Guild, domain: str, 
                           delete_channels: bool = False) -> Dict[str, Any]:
        """
        Remove a target from scope.
        Optionally delete all associated channels.
        """
        domain_clean = self.normalize_domain(domain)
        scope_key = f"{guild.id}_{domain_clean}"
        
        if scope_key not in self.scopes:
            return {
                "success": False,
                "error": f"Domain `{domain_clean}` is not in scope!"
            }
        
        scope = self.scopes[scope_key]
        
        try:
            if delete_channels:
                # Delete category and all channels
                category = guild.get_channel(scope.category_id)
                if category:
                    for channel in category.channels:
                        await channel.delete(reason="Scope removed")
                    await category.delete(reason="Scope removed")
            
            # Remove from data
            del self.scopes[scope_key]
            if guild.id in self.guild_scopes:
                if domain_clean in self.guild_scopes[guild.id]:
                    self.guild_scopes[guild.id].remove(domain_clean)
            
            self.save_data()
            
            return {
                "success": True,
                "domain": domain_clean,
                "channels_deleted": delete_channels
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_scope(self, guild_id: int, domain: str) -> Optional[TargetScope]:
        """Get scope data for a domain"""
        domain_clean = self.normalize_domain(domain)
        scope_key = f"{guild_id}_{domain_clean}"
        return self.scopes.get(scope_key)
    
    def get_guild_scopes(self, guild_id: int) -> List[TargetScope]:
        """Get all scopes for a guild"""
        domains = self.guild_scopes.get(guild_id, [])
        scopes = []
        for domain in domains:
            scope_key = f"{guild_id}_{domain}"
            if scope_key in self.scopes:
                scopes.append(self.scopes[scope_key])
        return scopes
    
    def get_channel_id(self, guild_id: int, domain: str, channel_type: str) -> Optional[int]:
        """Get channel ID for posting results"""
        scope = self.get_scope(guild_id, domain)
        if scope:
            return scope.channels.get(channel_type)
        return None
    
    async def post_to_channel(self, guild: discord.Guild, domain: str, 
                              channel_type: str, embed: discord.Embed = None,
                              content: str = None, file: discord.File = None,
                              view: discord.ui.View = None) -> bool:
        """
        Post results to the appropriate channel for a target.
        
        Args:
            guild: Discord guild
            domain: Target domain
            channel_type: Type of channel (subdomains, endpoints, etc.)
            embed: Embed to send
            content: Text content to send
            file: File to attach
            view: Discord View to include
            
        Returns:
            True if posted successfully
        """
        channel_id = self.get_channel_id(guild.id, domain, channel_type)
        if not channel_id:
            return False
        
        channel = guild.get_channel(channel_id)
        if not channel:
            return False
        
        try:
            await channel.send(content=content, embed=embed, file=file, view=view)
            return True
        except Exception as e:
            print(f"Error posting to channel: {e}")
            return False
    
    def chunk_list(self, items: List[str], chunk_size: int = 1000) -> List[str]:
        """Split a list of items into chunks of text < chunk_size"""
        chunks = []
        current_chunk = ""
        
        for item in items:
            # +1 for newline
            if len(current_chunk) + len(str(item)) + 1 > chunk_size:
                chunks.append(current_chunk)
                current_chunk = ""
            current_chunk += f"{item}\n"
            
        if current_chunk:
            chunks.append(current_chunk)
            
        return chunks

    async def post_subdomains(self, guild: discord.Guild, domain: str, 
                              subdomains: List[str], source: str = "Scan",
                              view: discord.ui.View = None):
        """Post discovered subdomains to the subdomains channel"""
        if not subdomains:
            return
        
        chunks = self.chunk_list(subdomains)
        total_parts = len(chunks)
        
        for i, chunk in enumerate(chunks):
            # Only show title on first part
            title = f"🌐 Subdomains Discovered ({i+1}/{total_parts})" if total_parts > 1 else "🌐 Subdomains Discovered"
            
            embed = discord.Embed(
                title=title,
                description=f"Part {i+1} of {total_parts}" if total_parts > 1 else f"Found **{len(subdomains)}** subdomains",
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            embed.add_field(name="Subdomains", value=f"```\n{chunk}\n```", inline=False)
            embed.set_footer(text=f"Source: {source} | Total: {len(subdomains)}")
            
            # Post with view only on the last chunk
            current_view = view if i == total_parts - 1 else None
            await self.post_to_channel(guild, domain, "subdomains", embed=embed, view=current_view)
    
    async def post_live_domains(self, guild: discord.Guild, domain: str,
                                live_domains: List[str], source: str = "Scan",
                                view: discord.ui.View = None):
        """Post live domains to the live-domains channel"""
        if not live_domains:
            return
        
        chunks = self.chunk_list(live_domains)
        total_parts = len(chunks)
        
        for i, chunk in enumerate(chunks):
            title = f"✅ Live Domains ({i+1}/{total_parts})" if total_parts > 1 else "✅ Live Domains"
            
            embed = discord.Embed(
                title=title,
                description=f"Part {i+1} of {total_parts}" if total_parts > 1 else f"Found **{len(live_domains)}** live domains",
                color=discord.Color.green(),
                timestamp=datetime.now()
            )
            
            embed.add_field(name="Live", value=f"```\n{chunk}\n```", inline=False)
            embed.set_footer(text=f"Source: {source} | Total: {len(live_domains)}")
            
            # Post with view only on the last chunk
            current_view = view if i == total_parts - 1 else None
            await self.post_to_channel(guild, domain, "live-domains", embed=embed, view=current_view)
    
    async def post_endpoints(self, guild: discord.Guild, domain: str,
                            endpoints: List[str], source: str = "Scan",
                            view: discord.ui.View = None):
        """Post endpoints to the endpoints channel"""
        if not endpoints:
            return
        
        chunks = self.chunk_list(endpoints)
        total_parts = len(chunks)
        
        for i, chunk in enumerate(chunks):
            title = f"🔗 Endpoints ({i+1}/{total_parts})" if total_parts > 1 else "🔗 Endpoints Discovered"
            
            embed = discord.Embed(
                title=title,
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            embed.add_field(name="Endpoints", value=f"```\n{chunk}\n```", inline=False)
            embed.set_footer(text=f"Source: {source} | Total: {len(endpoints)}")
            
            # Post with view only on the last chunk
            current_view = view if i == total_parts - 1 else None
            await self.post_to_channel(guild, domain, "endpoints", embed=embed, view=current_view)
    
    async def post_parameters(self, guild: discord.Guild, domain: str,
                             params: List[str], source: str = "Scan",
                             view: discord.ui.View = None):
        """Post parameters to the endpoints channel"""
        if not params:
            return
            
        chunks = self.chunk_list(params)
        total_parts = len(chunks)
        
        for i, chunk in enumerate(chunks):
            title = f"❓ Parameters ({i+1}/{total_parts})" if total_parts > 1 else "❓ Parameters Found"
            
            embed = discord.Embed(
                title=title,
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            embed.add_field(name="Parameters", value=f"```\n{chunk}\n```", inline=False)
            embed.set_footer(text=f"Source: {source} | Total: {len(params)}")
            
            # Post with view only on the last chunk
            current_view = view if i == total_parts - 1 else None
            # Merged into endpoints channel
            await self.post_to_channel(guild, domain, "endpoints", embed=embed, view=current_view)
    
    async def post_js_files(self, guild: discord.Guild, domain: str,
                           js_files: List[str], source: str = "Scan", view: discord.ui.View = None):
        """Post JS files to the endpoints channel and track them"""
        if not js_files:
            return
            
        # Track JS files for autocomplete
        self.add_js_files(domain, js_files)
            
        chunks = self.chunk_list(js_files)
        total_parts = len(chunks)
        
        for i, chunk in enumerate(chunks):
            title = f"📄 JS Files ({i+1}/{total_parts})" if total_parts > 1 else "📄 JavaScript Files"
            
            embed = discord.Embed(
                title=title,
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            embed.add_field(name="JS Files", value=f"```\n{chunk}\n```", inline=False)
            embed.set_footer(text=f"Source: {source} | Total: {len(js_files)}")
            
            # Post with view only on the last chunk or if provided
            current_view = view if i == total_parts - 1 else None
            await self.post_to_channel(guild, domain, "endpoints", embed=embed, view=current_view)
    
    async def post_technology(self, guild: discord.Guild, domain: str,
                             tech_data: Dict[str, Any], source: str = "Scan",
                             view: discord.ui.View = None):
        """Post technology detection results"""
        embed = discord.Embed(
            title=f"🔧 Technologies Detected",
            color=discord.Color.purple(),
            timestamp=datetime.now()
        )
        
        techs = tech_data.get('technologies', [])
        if techs:
            embed.add_field(name="Stack", value=f"```\n{', '.join(techs)}\n```", inline=False)
        
        headers = tech_data.get('headers', {})
        if headers:
            header_text = "\n".join([f"{k}: {v}" for k, v in list(headers.items())[:5]])
            embed.add_field(name="Headers", value=f"```\n{header_text}\n```", inline=False)
        
        embed.set_footer(text=f"Source: {source}")
        
        await self.post_to_channel(guild, domain, "technologies", embed=embed, view=view)
    
    async def post_vulnerability(self, guild: discord.Guild, domain: str,
                                vuln_data: Dict[str, Any], severity: str = "medium"):
        """Post vulnerability finding"""
        color_map = {
            "critical": discord.Color.dark_red(),
            "high": discord.Color.red(),
            "medium": discord.Color.orange(),
            "low": discord.Color.yellow(),
            "info": discord.Color.blue()
        }
        
        emoji_map = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        
        embed = discord.Embed(
            title=f"{emoji_map.get(severity, '⚪')} Vulnerability Found - {severity.upper()}",
            color=color_map.get(severity, discord.Color.grey()),
            timestamp=datetime.now()
        )
        
        embed.add_field(name="Type", value=f"`{vuln_data.get('type', 'Unknown')}`", inline=True)
        embed.add_field(name="Severity", value=f"`{severity}`", inline=True)
        
        if vuln_data.get('url'):
            embed.add_field(name="URL", value=f"```{vuln_data['url'][:200]}```", inline=False)
        
        if vuln_data.get('parameter'):
            embed.add_field(name="Parameter", value=f"`{vuln_data['parameter']}`", inline=True)
        
        if vuln_data.get('payload'):
            embed.add_field(name="Payload", value=f"```{vuln_data['payload'][:100]}```", inline=False)
        
        if vuln_data.get('evidence'):
            embed.add_field(name="Evidence", value=f"```{vuln_data['evidence'][:200]}```", inline=False)
        
        channel_type = "vulnerabilities" if severity in ["critical", "high"] else "potential-vulns"
        await self.post_to_channel(guild, domain, channel_type, embed=embed)
    
    async def post_cloud_finding(self, guild: discord.Guild, domain: str,
                                finding: Dict[str, Any]):
        """Post cloud asset finding"""
        embed = discord.Embed(
            title=f"☁️ Cloud Asset Found",
            color=discord.Color.orange(),
            timestamp=datetime.now()
        )
        
        embed.add_field(name="Type", value=f"`{finding.get('type', 'Unknown')}`", inline=True)
        embed.add_field(name="Public", value=f"`{'Yes' if finding.get('public') else 'No'}`", inline=True)
        
        if finding.get('url'):
            embed.add_field(name="URL", value=f"```{finding['url']}```", inline=False)
        
        await self.post_to_channel(guild, domain, "cloud-assets", embed=embed)
    
    async def post_secret(self, guild: discord.Guild, domain: str,
                         secret: Dict[str, Any]):
        """Post secret/leak finding"""
        embed = discord.Embed(
            title=f"🔐 Secret/Credential Found!",
            color=discord.Color.red(),
            timestamp=datetime.now()
        )
        
        embed.add_field(name="Type", value=f"`{secret.get('type', 'Unknown')}`", inline=True)
        embed.add_field(name="Value (masked)", value=f"`{secret.get('value', 'N/A')}`", inline=True)
        
        if secret.get('source'):
            embed.add_field(name="Source", value=f"```{secret['source'][:100]}```", inline=False)
        
        await self.post_to_channel(guild, domain, "secrets-leaks", embed=embed)
    
    async def post_note(self, guild: discord.Guild, domain: str,
                       note: str, author: discord.Member):
        """Post a note to the notes channel"""
        embed = discord.Embed(
            title=f"📋 Note",
            description=note,
            color=discord.Color.greyple(),
            timestamp=datetime.now()
        )
        embed.set_footer(text=f"By {author.name}")
        
        await self.post_to_channel(guild, domain, "notes", embed=embed)
    
    async def post_ports(self, guild: discord.Guild, domain: str,
                        port_data: Dict[str, Any], source: str = "Scan"):
        """Post port scan results"""
        embed = discord.Embed(
            title=f"🔌 Port Scan Results",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        open_ports = port_data.get('open_ports', [])
        if open_ports:
            embed.add_field(name="Open Ports", value=f"```{', '.join(map(str, open_ports))}```", inline=False)
        else:
            embed.add_field(name="Status", value="No open ports found in common range", inline=False)
        
        embed.add_field(name="Total Scanned", value=f"`{port_data.get('total_scanned', 0)}`", inline=True)
        embed.set_footer(text=f"Source: {source}")
        
        # Merged into live-domains as it relates to active services
        await self.post_to_channel(guild, domain, "live-domains", embed=embed)
    
    async def post_dns(self, guild: discord.Guild, domain: str,
                      dns_data: Dict[str, Any], source: str = "Scan"):
        """Post DNS records"""
        embed = discord.Embed(
            title=f"📝 DNS Records",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
            records = dns_data.get(record_type, [])
            if records:
                record_text = "\n".join(records[:5])
                embed.add_field(name=record_type, value=f"```{record_text}```", inline=True)
        
        embed.set_footer(text=f"Source: {source}")
        
        # Merged into subdomains as it is recon info
        await self.post_to_channel(guild, domain, "subdomains", embed=embed)
        
    async def post_finding(self, guild: discord.Guild, domain: str,
                           title: str, description: str, severity: str = "Info",
                           source: str = "Analysis", procedure: str = None,
                           view: discord.ui.View = None):
        """Post a security finding to the security-findings channel"""
        
        colors = {
            "Critical": discord.Color.dark_red(),
            "High": discord.Color.red(),
            "Medium": discord.Color.orange(),
            "Low": discord.Color.gold(),
            "Info": discord.Color.blue()
        }
        
        embed = discord.Embed(
            title=f"{severity.upper()}: {title}",
            description=description,
            color=colors.get(severity, discord.Color.blue()),
            timestamp=datetime.now()
        )
        
        if procedure:
            embed.add_field(name="📖 Manual Test Procedure", value=procedure, inline=False)
            
        embed.set_footer(text=f"Source: {source}")
        
        # Consolidated security channel
        await self.post_to_channel(guild, domain, "security-findings", embed=embed, view=view)

    # Legacy wrappers for compatibility (mapped to post_finding)
    async def post_vulnerability(self, guild: discord.Guild, domain: str,
                                vuln_data: Dict[str, Any], severity: str = "medium"):
        title = f"Vulnerability: {vuln_data.get('type', 'Unknown')}"
        desc = f"**Parameter**: `{vuln_data.get('parameter', 'N/A')}`\n" \
               f"**URL**: `{vuln_data.get('url', 'N/A')}`\n" \
               f"**Evidence**: `{vuln_data.get('evidence', 'N/A')}`"
        await self.post_finding(guild, domain, title, desc, severity.title(), "VulnScan")

    async def post_cloud_finding(self, guild: discord.Guild, domain: str, finding: Dict[str, Any]):
        title = f"Cloud Asset: {finding.get('type', 'Unknown')}"
        desc = f"**URL**: `{finding.get('url', 'N/A')}`\n**Public**: {finding.get('public', False)}"
        await self.post_finding(guild, domain, title, desc, "High" if finding.get('public') else "Info", "CloudScan")

    async def post_secret(self, guild: discord.Guild, domain: str, secret: Dict[str, Any]):
         title = f"Secret Leak: {secret.get('type', 'Unknown')}"
         desc = f"**Value**: `{secret.get('value', 'N/A')}`\n**Source**: `{secret.get('source', 'N/A')}`"
         await self.post_finding(guild, domain, title, desc, "Critical", "SecretScan")

    async def post_export(self, guild: discord.Guild, domain: str,
                         file: discord.File, description: str = "Exported Data"):
        """Post a file export to the exports channel"""
        embed = discord.Embed(
            title=f"📤 Data Export: {description}",
            description=f"File attached below.",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        embed.add_field(name="Target", value=f"`{domain}`", inline=True)
        
        result = await self.post_to_channel(guild, domain, "exports", embed=embed, file=file)
        return result



# Global scope manager instance
scope_manager = ScopeManager()


# Import here to avoid circular import
from .auto_scan import AutoScanManager

# Update scope manager to include auto-scan manager
scope_manager.auto_scan_manager = None  # Will be set after both managers are created
