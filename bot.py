import discord
from discord.ext import commands
from discord import app_commands
import asyncio
import aiohttp
import subprocess
import os
import json
import io
from datetime import datetime, timedelta
from typing import Optional, List, Any, Dict

# Import custom modules
from modules.recon import ReconTools
from modules.scanner import VulnScanner
from modules.httpx_tools import HttpxTools
from modules.utils import save_results, create_embed
from modules.suggestions import VulnerabilitySuggestions
from modules.advanced_tools import AdvancedTools
from modules.cloud_secrets import CloudSecrets
from modules.network_analysis import NetworkAnalysis
from modules.scope_manager import scope_manager, ScopeManager
from modules.auto_scan import auto_scan_manager, initialize_auto_scan_manager
from modules.wordlist_manager import check_and_create_wordlists
from modules.screenshot_utils import capture_screenshot

# Bot configuration
intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents)

# Store for scan results
scan_results = {}

# ============================================
# DROPDOWN MENU CLASSES
# ============================================

# ============================================
# VISUAL THEME CONFIGURATION
# ============================================
THEME_COLORS = {
    "primary": discord.Color.from_rgb(0, 255, 148),    # Neon Green
    "secondary": discord.Color.from_rgb(0, 200, 255),  # Cyan
    "warning": discord.Color.from_rgb(255, 165, 0),    # Orange
    "danger": discord.Color.from_rgb(255, 80, 80),     # Soft Red
    "info": discord.Color.from_rgb(100, 100, 255),     # Soft Blue
    "background": discord.Color.from_rgb(47, 49, 54),  # Dark Grey
}

class MainMenuView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        
    @discord.ui.select(
        placeholder="⚡ Access Bug Bounty Testing Tools",
        custom_id="main_menu_select",
        options=[
            discord.SelectOption(label="🎯 Scope Manager", value="scope", description="Configure targets & auto-create workspaces", emoji="🎯"),
            discord.SelectOption(label="🔍 Reconnaissance", value="recon", description="Subdomains, DNS, & Live Host detection", emoji="🔭"),
            discord.SelectOption(label="🌐 HTTP Analysis", value="httpx", description="Tech stack, Status codes, & Probing", emoji="🌐"),
            discord.SelectOption(label="⚡ Passive Analysis", value="vuln", description="Ethical pattern matching (No Active Exploits)", emoji="🛡️"),
            discord.SelectOption(label="📋 Target Filtering", value="filter", description="Find Login, Admin, & API endpoints", emoji="📥"),
            discord.SelectOption(label="🔗 URL Intelligence", value="url", description="Wayback data, Parameters, & JS Files", emoji="🔗"),
            discord.SelectOption(label="🚀 Advanced Recon", value="advanced", description="WAF, CMS, & Deep scanning tools", emoji="🚀"),
            discord.SelectOption(label="☁️ Cloud & Leaks", value="cloud", description="S3 Buckets, GitHub Dorks, & Secrets", emoji="☁️"),
            discord.SelectOption(label="🔐 Network Info", value="network", description="SSL, WHOIS, & Infrastructure data", emoji="📡"),
            discord.SelectOption(label="📊 Scan Results", value="results", description="View & Export your findings", emoji="📊"),
        ]
    )
    async def select_callback(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        embed = discord.Embed(color=THEME_COLORS["primary"])
        
        if selected == "scope":
            embed.title = "🎯 Scope Management"
            embed.description = "Add targets to your workspace to automatically create organized channels."
            await interaction.response.edit_message(embed=embed, view=ScopeMenuView())
        elif selected == "recon":
            embed.title = "🔍 Reconnaissance Tools"
            embed.description = "Gather initial intelligence on your target."
            await interaction.response.edit_message(embed=embed, view=ReconMenuView())
        elif selected == "httpx":
            embed.title = "🌐 HTTP Analysis Tools"
            embed.description = "Probe web servers and identify technologies."
            await interaction.response.edit_message(embed=embed, view=HttpxMenuView())
        elif selected == "vuln":
            embed.title = "⚡ Passive Vulnerability Analysis"
            embed.description = "Identify potential security hotspots without exploitation."
            await interaction.response.edit_message(embed=embed, view=VulnMenuView())
        elif selected == "filter":
            embed.title = "📋 Domain & Page Filtering"
            embed.description = "Quickly locate specific types of pages."
            await interaction.response.edit_message(embed=embed, view=FilterMenuView())
        elif selected == "url":
            embed.title = "🔗 URL Intelligence"
            embed.description = "Deep dive into URL parameters and history."
            await interaction.response.edit_message(embed=embed, view=UrlMenuView())
        elif selected == "advanced":
            embed.title = "🚀 Advanced Reconnaissance"
            embed.description = "Specialized tools for deeper analysis."
            await interaction.response.edit_message(embed=embed, view=AdvancedMenuView())
        elif selected == "cloud":
            embed.title = "☁️ Cloud Assets & Leaks"
            embed.description = "Discover cloud storage and potential information leaks."
            await interaction.response.edit_message(embed=embed, view=CloudMenuView())
        elif selected == "network":
            embed.title = "🔐 Network & Infrastructure"
            embed.description = "Analyze the underlying network security."
            await interaction.response.edit_message(embed=embed, view=NetworkMenuView())
        elif selected == "results":
            embed.title = "📊 Results Management"
            embed.description = "View stats or export your findings."
            await interaction.response.edit_message(embed=embed, view=ResultsMenuView())


class SuggestionsMenuView(discord.ui.View):
    """Menu for intelligent vulnerability suggestions"""
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="💡 Select Suggestion Type",
        options=[
            discord.SelectOption(label="Analyze Target", value="analyze", emoji="🔍", description="Detect tech & get suggestions"),
            discord.SelectOption(label="PHP/Laravel/WordPress", value="php", emoji="🐘"),
            discord.SelectOption(label="Node.js/Express/Next.js", value="nodejs", emoji="💚"),
            discord.SelectOption(label="Python/Django/Flask", value="python", emoji="🐍"),
            discord.SelectOption(label="Java/Spring", value="java", emoji="☕"),
            discord.SelectOption(label="GraphQL API", value="graphql", emoji="📊"),
            discord.SelectOption(label="REST API", value="rest_api", emoji="🔌"),
            discord.SelectOption(label="JWT Authentication", value="jwt", emoji="🔐"),
            discord.SelectOption(label="File Upload", value="file_upload", emoji="📁"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def suggestions_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        elif selected == "analyze":
            modal = SuggestionAnalyzeModal()
            await interaction.response.send_modal(modal)
        else:
            await show_tech_suggestions(interaction, selected)


class SuggestionAnalyzeModal(discord.ui.Modal):
    """Modal to input target for technology analysis"""
    def __init__(self):
        super().__init__(title="Analyze Target for Suggestions")
        
        self.target = discord.ui.TextInput(
            label="Target URL or Domain",
            placeholder="https://example.com or example.com",
            required=True,
            max_length=300
        )
        self.add_item(self.target)
        
    async def on_submit(self, interaction: discord.Interaction):
        target = self.target.value.strip()
        await interaction.response.defer()
        await analyze_target_for_suggestions(interaction, target)


class ReconMenuView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="🔍 Select Reconnaissance Tool",
        options=[
            discord.SelectOption(label="Subdomain Enumeration", value="subdomain", emoji="🌍"),
            discord.SelectOption(label="Live Domain Check", value="live_check", emoji="✅"),
            discord.SelectOption(label="Port Scanning", value="portscan", emoji="🔌"),
            discord.SelectOption(label="DNS Records", value="dns", emoji="📝"),
            discord.SelectOption(label="WHOIS Lookup", value="whois", emoji="🔎"),
            discord.SelectOption(label="Reverse IP Lookup", value="reverse_ip", emoji="🔄"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def recon_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        else:
            modal = DomainInputModal(tool_type="recon", action=selected)
            await interaction.response.send_modal(modal)


class HttpxMenuView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="🌐 Select HTTPX Tool",
        options=[
            discord.SelectOption(label="HTTP Probe (Live Check)", value="probe", emoji="🔍"),
            discord.SelectOption(label="Technology Detection", value="tech_detect", emoji="🔧"),
            discord.SelectOption(label="Status Code Filter", value="status_filter", emoji="📊"),
            discord.SelectOption(label="Title Extraction", value="title", emoji="📋"),
            discord.SelectOption(label="Content Length Check", value="content_length", emoji="📏"),
            discord.SelectOption(label="Screenshot Capture", value="screenshot", emoji="📸"),
            discord.SelectOption(label="Full HTTPX Scan", value="full_scan", emoji="🚀"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def httpx_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        else:
            modal = DomainInputModal(tool_type="httpx", action=selected)
            await interaction.response.send_modal(modal)


class VulnMenuView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="⚡ Select Passive Analysis Tool",
        options=[
            discord.SelectOption(label="Potential XSS Patterns", value="xss", emoji="🔍"),
            discord.SelectOption(label="Potential SQLi Patterns", value="sqli", emoji="🔍"),
            discord.SelectOption(label="Potential LFI Patterns", value="lfi", emoji="🔍"),
            discord.SelectOption(label="Potential Redirects", value="redirect", emoji="🔍"),
            discord.SelectOption(label="Potential SSRF Patterns", value="ssrf", emoji="🔍"),
            discord.SelectOption(label="CORS Configuration", value="cors", emoji="🌐"),
            discord.SelectOption(label="Security Headers", value="headers", emoji="🔒"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def vuln_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        else:
            modal = URLInputModal(tool_type="vuln", action=selected)
            await interaction.response.send_modal(modal)


class FilterMenuView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="📋 Select Domain Filter",
        options=[
            discord.SelectOption(label="Find Login Pages", value="login", emoji="🔐"),
            discord.SelectOption(label="Find Signup Pages", value="signup", emoji="📝"),
            discord.SelectOption(label="Find Admin Panels", value="admin", emoji="👤"),
            discord.SelectOption(label="Find API Endpoints", value="api", emoji="🔌"),
            discord.SelectOption(label="Find Forgot Password", value="forgot", emoji="🔑"),
            discord.SelectOption(label="Find Forms", value="forms", emoji="📋"),
            discord.SelectOption(label="Custom Keyword Filter", value="custom", emoji="🔍"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def filter_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        elif selected == "custom":
            modal = CustomFilterModal()
            await interaction.response.send_modal(modal)
        else:
            modal = DomainListInputModal(filter_type=selected)
            await interaction.response.send_modal(modal)


class URLMenuView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="🔗 Select URL Analysis Tool",
        options=[
            discord.SelectOption(label="Parameter Discovery", value="params", emoji="❓"),
            discord.SelectOption(label="Wayback URLs", value="wayback", emoji="📜"),
            discord.SelectOption(label="JS File Finder", value="js_files", emoji="📄"),
            discord.SelectOption(label="Endpoint Extraction", value="endpoints", emoji="🔗"),
            discord.SelectOption(label="Link Crawler", value="crawler", emoji="🕷️"),
            discord.SelectOption(label="Secret Finder", value="secrets", emoji="🔐"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def url_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        else:
            modal = DomainInputModal(tool_type="url", action=selected)
            await interaction.response.send_modal(modal)


class ResultsMenuView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="📊 Select Results Option",
        options=[
            discord.SelectOption(label="View Latest Results", value="view", emoji="👁️"),
            discord.SelectOption(label="Export to File", value="export", emoji="📁"),
            discord.SelectOption(label="Clear Results", value="clear", emoji="🗑️"),
            discord.SelectOption(label="Statistics", value="stats", emoji="📈"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def results_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        elif selected == "view":
            await view_results(interaction)
        elif selected == "export":
            await export_results(interaction)
        elif selected == "clear":
            await clear_results(interaction)
        elif selected == "stats":
            await show_stats(interaction)


class AdvancedMenuView(discord.ui.View):
    """Menu for advanced bug bounty tools"""
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="🚀 Select Advanced Tool",
        options=[
            discord.SelectOption(label="Directory Bruteforce", value="dirbust", emoji="📂"),
            discord.SelectOption(label="Subdomain Takeover Check", value="takeover", emoji="⚠️"),
            discord.SelectOption(label="WAF Detection", value="waf", emoji="🛡️"),
            discord.SelectOption(label="CMS Detection", value="cms", emoji="📝"),
            discord.SelectOption(label="Robots.txt Analyzer", value="robots", emoji="🤖"),
            discord.SelectOption(label="Sitemap Parser", value="sitemap", emoji="🗺️"),
            discord.SelectOption(label="HTTP Methods Check", value="methods", emoji="📨"),
            discord.SelectOption(label="Security Headers Scan", value="headers_full", emoji="🔒"),
            discord.SelectOption(label="Favicon Hash", value="favicon", emoji="🎭"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def advanced_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        else:
            modal = DomainInputModal(tool_type="advanced", action=selected)
            await interaction.response.send_modal(modal)


class CloudMenuView(discord.ui.View):
    """Menu for cloud and secrets discovery tools"""
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="☁️ Select Cloud/Secrets Tool",
        options=[
            discord.SelectOption(label="S3 Bucket Finder", value="s3", emoji="🪣"),
            discord.SelectOption(label="Azure Blob Finder", value="azure", emoji="📘"),
            discord.SelectOption(label="GCP Bucket Finder", value="gcp", emoji="🟢"),
            discord.SelectOption(label="Secret Scanner", value="secrets", emoji="🔐"),
            discord.SelectOption(label="GitHub Dork Generator", value="github_dorks", emoji="🐙"),
            discord.SelectOption(label="Google Dork Generator", value="google_dorks", emoji="🔍"),
            discord.SelectOption(label="Shodan Dork Generator", value="shodan_dorks", emoji="👁️"),
            discord.SelectOption(label="Email Harvester", value="emails", emoji="📧"),
            discord.SelectOption(label="Firebase Check", value="firebase", emoji="🔥"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def cloud_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        else:
            modal = DomainInputModal(tool_type="cloud", action=selected)
            await interaction.response.send_modal(modal)


class NetworkMenuView(discord.ui.View):
    """Menu for network and SSL analysis tools"""
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="🔐 Select Network/SSL Tool",
        options=[
            discord.SelectOption(label="SSL Certificate Analysis", value="ssl", emoji="🔒"),
            discord.SelectOption(label="SSL Vulnerability Check", value="ssl_vuln", emoji="⚠️"),
            discord.SelectOption(label="ASN Lookup", value="asn", emoji="🌐"),
            discord.SelectOption(label="CDN Detection", value="cdn", emoji="⚡"),
            discord.SelectOption(label="DNS Zone Transfer", value="zone_transfer", emoji="📡"),
            discord.SelectOption(label="Reverse DNS", value="reverse_dns", emoji="🔄"),
            discord.SelectOption(label="Host Alive Check", value="alive", emoji="🟢"),
            discord.SelectOption(label="Enhanced WHOIS", value="whois_full", emoji="📝"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def network_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        else:
            await interaction.response.send_modal(modal)


class JSFileSelector(discord.ui.Select):
    """Dropdown for selecting discovered JS files to quickly analyze"""
    def __init__(self, js_files: List[str], domain: str = None):
        self.js_files_map = {}
        options = []
        for i, url in enumerate(js_files[:25]): # Discord limit is 25
            # Store original URL in map using index as key
            self.js_files_map[str(i)] = url
            
            # Clean up label
            label = url.split('/')[-1]
            if not label: label = url
            if len(label) > 80: label = label[:77] + "..."
            
            # Truncate description
            desc = f"Analyze {domain or 'component'}"
            if not domain:
                desc = url[:100]
            
            options.append(discord.SelectOption(
                label=f"📄 {label}",
                value=str(i),
                description=desc[:100]
            ))
            
        super().__init__(
            placeholder="📦 Select a JavaScript file to analyze...",
            min_values=1,
            max_values=1,
            options=options
        )

    async def callback(self, interaction: discord.Interaction):
        url = self.js_files_map.get(self.values[0])
        if url:
            # Call processing function instead of command object
            await process_analyze_js(interaction, url=url)
        else:
            await interaction.response.send_message("❌ Error: Selected URL not found.", ephemeral=True)


class JSFileView(discord.ui.View):
    """View containing the JS file selector dropdown"""
    def __init__(self, js_files: List[str], domain: str = None):
        super().__init__(timeout=None)
        self.add_item(JSFileSelector(js_files, domain))


def create_channel_view(channel_name: str, domain: str) -> discord.ui.View:
    """Create channel-specific button views"""
    view = discord.ui.View(timeout=None)
    
    if channel_name == "subdomains":
        btn = discord.ui.Button(label="🌐 Find Subdomains", style=discord.ButtonStyle.green)
        async def callback(interaction):
            await interaction.response.defer()
            await process_quick_sub(interaction, domain)
        btn.callback = callback
        view.add_item(btn)
        
    elif channel_name == "live-domains":
        btn = discord.ui.Button(label="✅ Check Live Hosts", style=discord.ButtonStyle.green)
        async def callback(interaction):
            await interaction.response.defer()
            await process_quick_live(interaction, domain)
        btn.callback = callback
        view.add_item(btn)
        
    elif channel_name == "endpoints":
        btn = discord.ui.Button(label="🔗 Extract Endpoints", style=discord.ButtonStyle.blurple)
        async def callback(interaction):
            await interaction.response.defer()
            await process_url_tools(interaction, "endpoints", domain)
        btn.callback = callback
        view.add_item(btn)
        
        btn2 = discord.ui.Button(label="📄 Find JS Files", style=discord.ButtonStyle.secondary)
        async def callback2(interaction):
            await interaction.response.defer()
            await process_url_tools(interaction, "js_files", domain)
        btn2.callback = callback2
        view.add_item(btn2)
        
    elif channel_name == "screenshots":
        btn = discord.ui.Button(label="📸 Capture All Live", style=discord.ButtonStyle.green)
        async def callback(interaction):
            await interaction.response.defer()
            await process_httpx(interaction, "screenshot", domain)
        btn.callback = callback
        view.add_item(btn)
        
    elif channel_name == "security-findings":
        btn = discord.ui.Button(label="🧠 Run Smart Analysis", style=discord.ButtonStyle.danger)
        async def callback(interaction):
            await interaction.response.defer()
            await process_full_scan(interaction, domain) # Full scan includes analysis
        btn.callback = callback
        view.add_item(btn)
    
    else: # Default for notes, reports, etc.
        btn = discord.ui.Button(label="🚀 Run Full Scan", style=discord.ButtonStyle.green)
        async def callback(interaction):
            await interaction.response.defer()
            await process_full_scan(interaction, domain)
        btn.callback = callback
        view.add_item(btn)
    
    return view


class ChannelScanView(discord.ui.View):
    """Fallback generic view"""
    def __init__(self, domain: str):
        super().__init__(timeout=None)
        self.domain = domain
        
    @discord.ui.button(label="🚀 Run Full Scan", style=discord.ButtonStyle.green, custom_id="run_full_scan_fallback")
    async def run_full(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        await process_full_scan(interaction, self.domain)


class ScopeMenuView(discord.ui.View):
    """Menu for scope management"""
    def __init__(self):
        super().__init__(timeout=300)
        
    @discord.ui.select(
        placeholder="🎯 Select Scope Action",
        options=[
            discord.SelectOption(label="Add Target to Scope", value="add", emoji="➕", description="Create category & channels for domain"),
            discord.SelectOption(label="Remove Target from Scope", value="remove", emoji="➖", description="Remove domain from scope"),
            discord.SelectOption(label="List All Scopes", value="list", emoji="📋", description="Show all scoped targets"),
            discord.SelectOption(label="Full Recon Scan", value="full_scan", emoji="🚀", description="Run complete scan on scoped target"),
            discord.SelectOption(label="Add Note", value="note", emoji="📝", description="Add note to target"),
            discord.SelectOption(label="Quick Subdomain Enum", value="quick_sub", emoji="🌐", description="Fast subdomain scan"),
            discord.SelectOption(label="Quick Live Check", value="quick_live", emoji="✅", description="Check live domains"),
            discord.SelectOption(label="Auto-Scan Setup", value="autoscan_setup", emoji="🔄", description="Create scheduled scans"),
            discord.SelectOption(label="List Auto-Scans", value="list_autoscan", emoji="📋", description="Show scheduled scans"),
            discord.SelectOption(label="Stop Auto-Scan", value="stop_autoscan", emoji="⏹️", description="Stop scheduled scan"),
            discord.SelectOption(label="🔙 Back to Main Menu", value="back", emoji="⬅️"),
        ]
    )
    async def scope_select(self, interaction: discord.Interaction, select: discord.ui.Select):
        selected = select.values[0]
        
        if selected == "back":
            await interaction.response.edit_message(content="**🛠️ Bug Bounty Tools**", view=MainMenuView())
        elif selected in ["add", "remove", "full_scan", "note", "quick_sub", "quick_live"]:
            modal = ScopeActionModal(action=selected)
            await interaction.response.send_modal(modal)
        elif selected == "list":
            await process_list_scopes(interaction)
        elif selected in ["autoscan_setup", "list_autoscan", "stop_autoscan"]:
            if selected == "autoscan_setup":
                modal = AutoScanSetupModal()
                await interaction.response.send_modal(modal)
            elif selected == "list_autoscan":
                await process_list_auto_scans(interaction)
            elif selected == "stop_autoscan":
                modal = StopAutoScanModal()
                await interaction.response.send_modal(modal)


class ScopeActionModal(discord.ui.Modal):
    """Modal for scope actions"""
    def __init__(self, action: str):
        self.action = action
        title_map = {
            "add": "Add Target to Scope",
            "remove": "Remove Target from Scope",
            "full_scan": "Full Recon Scan",
            "note": "Add Note to Target",
            "quick_sub": "Quick Subdomain Scan",
            "quick_live": "Quick Live Domain Check"
        }
        super().__init__(title=title_map.get(action, "Scope Action"))
        
        self.domain = discord.ui.TextInput(
            label="Target Domain",
            placeholder="example.com",
            required=True,
            max_length=200
        )
        self.add_item(self.domain)
        
        if action == "note":
            self.note = discord.ui.TextInput(
                label="Note",
                style=discord.TextStyle.paragraph,
                placeholder="Your note here...",
                required=True,
                max_length=1000
            )
            self.add_item(self.note)
        
        elif action == "remove":
            self.delete_channels = discord.ui.TextInput(
                label="Delete Channels Too? (yes/no)",
                placeholder="no",
                required=False,
                max_length=3
            )
            self.add_item(self.delete_channels)
        
        elif action in ["quick_sub", "quick_live"]:
            self.limit = discord.ui.TextInput(
                label="Limit (optional)",
                placeholder="100",
                required=False,
                max_length=10
            )
            self.add_item(self.limit)
    
    async def on_submit(self, interaction: discord.Interaction):
        domain = self.domain.value.strip()
        await interaction.response.defer()
        
        if self.action == "add":
            await process_add_scope(interaction, domain)
        elif self.action == "remove":
            delete_channels = self.delete_channels.value.strip().lower() == "yes"
            await process_remove_scope(interaction, domain, delete_channels)
        elif self.action == "full_scan":
            await process_full_scan(interaction, domain)
        elif self.action == "note":
            note = self.note.value.strip()
            await process_add_note(interaction, domain, note)
        elif self.action == "quick_sub":
            await process_quick_sub(interaction, domain)
        elif self.action == "quick_live":
            await process_quick_live(interaction, domain)


# ============================================
# MODAL CLASSES FOR INPUT
# ============================================

class DomainInputModal(discord.ui.Modal):
    def __init__(self, tool_type: str, action: str):
        super().__init__(title=f"Enter Target Domain")
        self.tool_type = tool_type
        self.action = action
        
        self.domain = discord.ui.TextInput(
            label="Target Domain",
            placeholder="example.com",
            required=True,
            max_length=200
        )
        self.add_item(self.domain)
        
    async def on_submit(self, interaction: discord.Interaction):
        domain = self.domain.value.strip()
        await interaction.response.defer()
        
        # Process based on tool type
        if self.tool_type == "recon":
            await process_recon(interaction, self.action, domain)
        elif self.tool_type == "httpx":
            await process_httpx(interaction, self.action, domain)
        elif self.tool_type == "url":
            await process_url_tools(interaction, self.action, domain)
        elif self.tool_type == "advanced":
            await process_advanced_tools(interaction, self.action, domain)
        elif self.tool_type == "cloud":
            await process_cloud_tools(interaction, self.action, domain)
        elif self.tool_type == "network":
            await process_network_tools(interaction, self.action, domain)


class URLInputModal(discord.ui.Modal):
    def __init__(self, tool_type: str, action: str):
        super().__init__(title=f"Enter Target URL")
        self.tool_type = tool_type
        self.action = action
        
        self.url = discord.ui.TextInput(
            label="Target URL",
            placeholder="https://example.com/page?param=value",
            required=True,
            max_length=500
        )
        self.add_item(self.url)
        
    async def on_submit(self, interaction: discord.Interaction):
        url = self.url.value.strip()
        await interaction.response.defer()
        
        if self.tool_type == "vuln":
            await process_vuln_scan(interaction, self.action, url)


class DomainListInputModal(discord.ui.Modal):
    def __init__(self, filter_type: str):
        super().__init__(title=f"Enter Domain or Domain List")
        self.filter_type = filter_type
        
        self.domains = discord.ui.TextInput(
            label="Domains (one per line or comma-separated)",
            style=discord.TextStyle.paragraph,
            placeholder="example1.com\nexample2.com\nor\nexample1.com, example2.com",
            required=True,
            max_length=2000
        )
        self.add_item(self.domains)
        
    async def on_submit(self, interaction: discord.Interaction):
        domains_input = self.domains.value.strip()
        await interaction.response.defer()
        await process_domain_filter(interaction, self.filter_type, domains_input)


class CustomFilterModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Custom Keyword Filter")
        
        self.domains = discord.ui.TextInput(
            label="Domains (one per line)",
            style=discord.TextStyle.paragraph,
            placeholder="example1.com\nexample2.com",
            required=True,
            max_length=2000
        )
        self.add_item(self.domains)
        
        self.keywords = discord.ui.TextInput(
            label="Keywords to search (comma-separated)",
            placeholder="dashboard, portal, account",
            required=True,
            max_length=500
        )
        self.add_item(self.keywords)
        
    async def on_submit(self, interaction: discord.Interaction):
        domains = self.domains.value.strip()
        keywords = self.keywords.value.strip()
        await interaction.response.defer()
        await process_custom_filter(interaction, domains, keywords)


class AutoScanSetupModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Setup Auto-Scan")
        
        self.domain = discord.ui.TextInput(
            label="Target Domain (must be in scope)",
            placeholder="example.com",
            required=True,
            max_length=200
        )
        self.add_item(self.domain)
        
        self.scan_type = discord.ui.TextInput(
            label="Scan Type (full, subdomain, live, tech, vuln)",
            placeholder="full",
            required=True,
            max_length=20
        )
        self.add_item(self.scan_type)
        
        self.interval = discord.ui.TextInput(
            label="Interval (minutes)",
            placeholder="60",
            required=True,
            max_length=10
        )
        self.add_item(self.interval)
    
    async def on_submit(self, interaction: discord.Interaction):
        domain = self.domain.value.strip()
        scan_type = self.scan_type.value.strip().lower()
        try:
            interval = int(self.interval.value.strip())
        except ValueError:
            await interaction.response.send_message("❌ Interval must be a number!", ephemeral=True)
            return
        
        await interaction.response.defer()
        
        scope = scope_manager.get_scope(interaction.guild.id, domain)
        if not scope:
            embed = discord.Embed(
                title="❌ Domain Not in Scope",
                description=f"`{domain}` is not in scope. Add it first with `/addscope {domain}`",
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed)
            return
        
        # Get the subdomains channel for notifications
        channel_id = scope_manager.get_channel_id(interaction.guild.id, domain, "subdomains")
        if not channel_id:
            channel_id = interaction.channel.id  # Fallback to current channel
        
        try:
            task_id = await auto_scan_manager.create_scan_task(
                domain=domain,
                guild_id=interaction.guild.id,
                channel_id=channel_id,
                scan_type=scan_type,
                interval_minutes=interval
            )
            
            embed = discord.Embed(
                title="✅ Auto-Scan Created!",
                description=f"Created scheduled {scan_type} scan for `{domain}`",
                color=discord.Color.green()
            )
            embed.add_field(name="Task ID", value=f"`{task_id}`", inline=True)
            embed.add_field(name="Interval", value=f"Every {interval} minutes", inline=True)
            embed.add_field(name="Next Run", value=f"<t:{int((datetime.now() + timedelta(minutes=interval)).timestamp())}:R>", inline=True)
            
            await interaction.followup.send(embed=embed)
            
        except Exception as e:
            embed = discord.Embed(
                title="❌ Error Creating Auto-Scan",
                description=f"{str(e)}",
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed)


class StopAutoScanModal(discord.ui.Modal):
    def __init__(self):
        super().__init__(title="Stop Auto-Scan")
        
        self.task_id = discord.ui.TextInput(
            label="Task ID to Stop",
            placeholder="Enter the auto-scan task ID",
            required=True,
            max_length=100
        )
        self.add_item(self.task_id)
    
    async def on_submit(self, interaction: discord.Interaction):
        task_id = self.task_id.value.strip()
        
        if task_id in auto_scan_manager.scan_tasks:
            await auto_scan_manager.disable_task(task_id)
            embed = discord.Embed(
                title="✅ Auto-Scan Stopped",
                description=f"Auto-scan `{task_id}` has been disabled",
                color=discord.Color.green()
            )
        else:
            embed = discord.Embed(
                title="❌ Task Not Found",
                description=f"No auto-scan with ID `{task_id}` found",
                color=discord.Color.red()
            )
        
        await interaction.response.send_message(embed=embed)


# ============================================
# PROCESSING FUNCTIONS
# ============================================

async def process_recon(interaction: discord.Interaction, action: str, domain: str):
    """Process reconnaissance actions"""
    
    embed = discord.Embed(
        title=f"🔍 Running: {action.replace('_', ' ').title()}",
        description=f"Target: `{domain}`",
        color=THEME_COLORS["warning"],
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Scanning...", inline=False)
    msg = await interaction.followup.send(embed=embed)
    
    try:
        if action == "subdomain":
            async with ReconTools() as recon:
                results = await recon.subdomain_enum(domain)
        elif action == "live_check":
            domains = [f"http://{domain}", f"https://{domain}"]
            async with HttpxTools() as httpx:
                results = await httpx.probe_domains(domains)
        elif action == "portscan":
            async with ReconTools() as recon:
                results = await recon.port_scan(domain)
        elif action == "dns":
            async with ReconTools() as recon:
                results = await recon.dns_records(domain)
        elif action == "whois":
            async with ReconTools() as recon:
                results = await recon.whois_lookup(domain)
        elif action == "reverse_ip":
            async with ReconTools() as recon:
                results = await recon.reverse_ip(domain)
        else:
            results = {"error": "Unknown action"}
        
        embed.color = THEME_COLORS["primary"]
        embed.clear_fields()
        
        # Format results based on type
        if action == "subdomain":
            embed.add_field(name="Found", value=f"`{len(results)}` subdomains", inline=False)
            
            if len(results) > 50:
                # Create export file for large results
                try:
                    file_content = "\n".join(results)
                    file_obj = io.BytesIO(file_content.encode('utf-8'))
                    discord_file = discord.File(file_obj, filename=f"subdomains_{domain}.txt")
                    
                    # Attempt export to #exports channel
                    if hasattr(scope_manager, 'post_export'):
                        await scope_manager.post_export(interaction.guild, domain, discord_file, "Subdomain List")
                        embed.add_field(name="📂 Export", value="**Full list sent to #exports channel**", inline=False)
                except Exception as ex:
                    print(f"Export failed: {ex}")

                # Show preview in embed
                chunk = "\n".join(results[:25])
                embed.add_field(name="Subdomains (Top 25)", value=f"```\n{chunk}\n```", inline=False)
            elif results:
                chunk = "\n".join(results)
                embed.add_field(name="Subdomains", value=f"```\n{chunk}\n```", inline=False)
        
        elif action == "portscan":
            ports = results.get('open_ports', [])
            if ports:
                embed.color = THEME_COLORS["danger"]
                embed.add_field(name="Open Ports", value=f"```\n{', '.join(map(str, ports))}\n```", inline=False)
            else:
                embed.add_field(name="Status", value="✅ No open ports found in common list", inline=False)
        
        else:
            # Generic JSON dump for now
            result_text = json.dumps(results, indent=2, default=str)[:1800]
            embed.add_field(name="✅ Results", value=f"```json\n{result_text}\n```", inline=False)
        
        scan_results[f"recon_{action}_{domain}"] = results
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = THEME_COLORS["danger"]
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed, view=ReconMenuView())


async def process_httpx(interaction: discord.Interaction, action: str, domain: str):
    """Process HTTPX actions"""
    httpx = HttpxTools()
    
    embed = discord.Embed(
        title=f"🌐 Running: {action.replace('_', ' ').title()}",
        description=f"Target: `{domain}`",
        color=THEME_COLORS["warning"],
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Analyzing...", inline=False)
    msg = await interaction.followup.send(embed=embed)
    
    try:
        if action == "tech_detect":
            results = await httpx.detect_technology(domain)
        elif action == "probe":
            results = await httpx.probe_domains([domain])
        elif action == "status_filter":
            results = await httpx.probe_domains([domain])
        elif action == "title":
            results = await httpx.probe_domains([domain])
        elif action == "screenshot":
             embed.description = f"📸 Capturing screenshot for `{domain}`..."
             await msg.edit(embed=embed)
             screenshot_file = await capture_screenshot(domain)
             if screenshot_file:
                 embed.color = THEME_COLORS["primary"]
                 embed.clear_fields()
                 embed.add_field(name="✅ Status", value="Screenshot captured successfully", inline=False)
                 embed.set_image(url="attachment://screenshot.png")
                 await msg.edit(embed=embed, file=screenshot_file, view=MainMenuView())
                 return
             else:
                 results = {"error": "Failed to capture screenshot (Playwright might not be installed or site is unreachable)"}
        else:
            # Fallback
            results = await httpx.probe_domains([domain])
        
        embed.color = THEME_COLORS["secondary"]
        embed.clear_fields()
        
        if action == "tech_detect":
            techs = results.get('technologies', [])
            if techs:
                embed.add_field(name="🛠️ Stack", value=f"```\n{', '.join(techs)}\n```", inline=False)
            headers = results.get('headers', {})
            if headers:
                h_text = "\n".join([f"{k}: {v}" for k, v in list(headers.items())[:5]])
                embed.add_field(name="🔒 Headers", value=f"```\n{h_text}\n```", inline=False)
        else:
            result_text = json.dumps(results, indent=2, default=str)[:1800]
            embed.add_field(name="✅ Results", value=f"```json\n{result_text}\n```", inline=False)
            
        scan_results[f"httpx_{action}_{domain}"] = results
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = THEME_COLORS["danger"]
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed, view=HttpxMenuView())


async def process_vuln_scan(interaction: discord.Interaction, action: str, url: str):
    """Process passive vulnerability analysis actions"""
    scanner = VulnScanner()
    
    embed = discord.Embed(
        title=f"⚡ Passive Analysis: {action.upper()}",
        description=f"Target: `{url}`",
        color=THEME_COLORS["warning"],
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Analyzing patterns (Passive)...", inline=False)
    msg = await interaction.followup.send(embed=embed)
    
    try:
        # Use simple analyze_url for all (wrapper in scanner.py handles dispatch)
        results = await scanner.analyze_url(url)
        
        # Determine status
        issues = results.get("potential_issues", [])
        
        embed.color = THEME_COLORS["warning"] if issues else THEME_COLORS["secondary"]
        embed.clear_fields()
        
        if issues:
            embed.add_field(name="⚠️ Potential Issues Detected", value=f"Found {len(issues)} items of interest", inline=False)
            
            for issue in issues[:8]:
                embed.add_field(
                    name=f"{issue.get('type', 'Unknown')}", 
                    value=f"Param: `{issue.get('parameter', 'N/A')}`\nDesc: {issue.get('description', '')[:100]}", 
                    inline=True
                )
        else:
            embed.add_field(name="✅ Status", value="No obvious patterns detected in parameters/headers.", inline=False)
            
        if "security_headers" in results:
             missing = [h for h, v in results["security_headers"].items() if not v["present"]]
             if missing:
                 embed.add_field(name="Missing Headers", value=f"```\n{', '.join(missing)}\n```", inline=False)
        
        scan_results[f"vuln_{action}_{url}"] = results
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = THEME_COLORS["danger"]
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed, view=MainMenuView())


async def process_domain_filter(interaction: discord.Interaction, filter_type: str, domains_input: str):
    """Process domain filtering for login/signup pages"""
    # Parse domains
    if '\n' in domains_input:
        domains = [d.strip() for d in domains_input.split('\n') if d.strip()]
    else:
        domains = [d.strip() for d in domains_input.split(',') if d.strip()]
    
    filter_keywords = {
        "login": ["login", "signin", "sign-in", "auth", "authenticate", "logon"],
        "signup": ["signup", "sign-up", "register", "registration", "create-account", "join"],
        "admin": ["admin", "administrator", "dashboard", "panel", "backend", "manage"],
        "api": ["api", "graphql", "rest", "endpoint", "v1", "v2", "v3"],
        "forgot": ["forgot", "reset", "password", "recover", "forgot-password"],
        "forms": ["form", "submit", "contact", "feedback", "survey"]
    }
    
    keywords = filter_keywords.get(filter_type, [])
    
    embed = discord.Embed(
        title=f"📋 Filtering: {filter_type.title()} Pages",
        description=f"Scanning `{len(domains)}` domains",
        color=THEME_COLORS["warning"],
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Filtering domains...", inline=False)
    msg = await interaction.followup.send(embed=embed)
    
    try:
        httpx = HttpxTools()
        found_pages = []
        
        for domain in domains:
            # Check common paths for each filter type
            paths_to_check = generate_filter_paths(filter_type, domain)
            live_results = await httpx.probe_domains(paths_to_check)
            found_pages.extend(live_results)
        
        embed.color = THEME_COLORS["secondary"]
        embed.clear_fields()
        
        if found_pages:
            result_text = "\n".join(found_pages[:30])
            if len(found_pages) > 30:
                result_text += f"\n... and {len(found_pages) - 30} more"
            embed.add_field(name=f"✅ Found {filter_type.title()} Pages", value=f"```\n{result_text}\n```", inline=False)
        else:
            embed.add_field(name="Results", value="```No matching pages found```", inline=False)
        
        embed.add_field(name="Total Found", value=f"`{len(found_pages)}`", inline=True)
        
        scan_results[f"filter_{filter_type}"] = found_pages
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = THEME_COLORS["danger"]
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed, view=MainMenuView())


async def process_custom_filter(interaction: discord.Interaction, domains_input: str, keywords_input: str):
    """Process custom keyword filtering"""
    if '\n' in domains_input:
        domains = [d.strip() for d in domains_input.split('\n') if d.strip()]
    else:
        domains = [d.strip() for d in domains_input.split(',') if d.strip()]
    
    keywords = [k.strip() for k in keywords_input.split(',') if k.strip()]
    
    embed = discord.Embed(
        title="🔍 Custom Keyword Filter",
        description=f"Scanning `{len(domains)}` domains for keywords: `{', '.join(keywords)}`",
        color=THEME_COLORS["warning"],
        timestamp=datetime.now()
    )
    msg = await interaction.followup.send(embed=embed)
    
    try:
        httpx = HttpxTools()
        found_pages = []
        
        for domain in domains:
            for keyword in keywords:
                urls_to_check = [
                    f"https://{domain}/{keyword}",
                    f"https://{domain}/{keyword}.php",
                    f"https://{domain}/{keyword}.html",
                    f"http://{domain}/{keyword}",
                ]
                results = await httpx.probe_domains(urls_to_check)
                found_pages.extend(results)
        
        embed.color = THEME_COLORS["secondary"]
        embed.clear_fields()
        
        if found_pages:
            result_text = "\n".join(list(set(found_pages))[:30])
            embed.add_field(name="✅ Found Pages", value=f"```\n{result_text}\n```", inline=False)
        else:
            embed.add_field(name="Results", value="```No matching pages found```", inline=False)
        
        scan_results["custom_filter"] = found_pages
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = THEME_COLORS["danger"]
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed, view=MainMenuView())


async def process_url_tools(interaction: discord.Interaction, action: str, domain: str):
    """Process URL analysis tools"""
    
    embed = discord.Embed(
        title=f"🔗 URL Analysis: {action.replace('_', ' ').title()}",
        description=f"Target: `{domain}`",
        color=THEME_COLORS["warning"],
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Analyzing...", inline=False)
    msg = await interaction.followup.send(embed=embed)
    
    try:
        async with ReconTools() as recon:
            if action == "params":
                results = await recon.find_parameters(domain)
            elif action == "wayback":
                results = await recon.wayback_urls(domain)
            elif action == "js_files":
                results = await recon.find_js_files(domain)
            elif action == "endpoints":
                results = await recon.extract_endpoints(domain)
            elif action == "crawler":
                results = await recon.crawl_links(domain)
            elif action == "secrets":
                results = await recon.find_secrets_for_domain(domain)
            else:
                results = {"error": "Unknown action"}
        
        embed.color = THEME_COLORS["secondary"]
        embed.clear_fields()
        
        if isinstance(results, list):
            if results and isinstance(results[0], dict):
                # Structured findings (secrets)
                result_text = ""
                for s in results[:10]:
                    result_text += f"• **{s['type']}**: `{s['value']}`\n"
                if len(results) > 10: result_text += f"... and {len(results)-10} more"
            else:
                # Plain strings (endpoints, params, etc)
                result_text = "\n".join(results[:40]) if results else "No results found"
                if len(result_text) > 1000:
                    result_text = result_text[:997] + "..."
            
            embed.add_field(name="✅ Results", value=f"```\n{result_text}\n```" if result_text != "No results found" else result_text, inline=False)
            embed.add_field(name="Total Found", value=f"`{len(results)}`", inline=True)
            
            # If JS files we found, show the selector view
            if action == "js_files" and results:
                view = JSFileView(results, domain)
                await msg.edit(embed=embed, view=view)
                return
        else:
            embed.add_field(name="Results", value=f"```{str(results)[:1900]}```", inline=False)
        
        scan_results[f"url_{action}_{domain}"] = results
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        error_msg = str(e)
        if len(error_msg) > 1000: error_msg = error_msg[:997] + "..."
        
        embed.color = THEME_COLORS["danger"]
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{error_msg}```", inline=False)
        await msg.edit(embed=embed, view=MainMenuView())


def generate_filter_paths(filter_type: str, domain: str) -> list:
    """Generate common paths based on filter type"""
    paths = {
        "login": [
            f"https://{domain}/login", f"https://{domain}/signin", f"https://{domain}/auth",
            f"https://{domain}/admin/login", f"https://{domain}/user/login",
            f"https://{domain}/account/login", f"https://{domain}/wp-login.php",
            f"http://{domain}/login", f"http://{domain}/signin"
        ],
        "signup": [
            f"https://{domain}/signup", f"https://{domain}/register", f"https://{domain}/join",
            f"https://{domain}/create-account", f"https://{domain}/sign-up",
            f"https://{domain}/user/register", f"http://{domain}/signup"
        ],
        "admin": [
            f"https://{domain}/admin", f"https://{domain}/administrator", f"https://{domain}/dashboard",
            f"https://{domain}/wp-admin", f"https://{domain}/panel", f"https://{domain}/backend",
            f"https://{domain}/manage", f"https://{domain}/control"
        ],
        "api": [
            f"https://{domain}/api", f"https://{domain}/api/v1", f"https://{domain}/api/v2",
            f"https://{domain}/graphql", f"https://{domain}/rest", f"https://{domain}/api/docs",
            f"https://{domain}/swagger", f"https://{domain}/api-docs"
        ],
        "forgot": [
            f"https://{domain}/forgot-password", f"https://{domain}/reset-password",
            f"https://{domain}/password/reset", f"https://{domain}/recover",
            f"https://{domain}/forgot", f"https://{domain}/password-reset"
        ],
        "forms": [
            f"https://{domain}/contact", f"https://{domain}/contact-us", f"https://{domain}/feedback",
            f"https://{domain}/submit", f"https://{domain}/form", f"https://{domain}/inquiry"
        ]
    }
    return paths.get(filter_type, [])


async def view_results(interaction: discord.Interaction):
    """View latest scan results"""
    if not scan_results:
        await interaction.response.send_message("📭 No scan results available yet.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="📊 Scan Results Summary",
        color=THEME_COLORS["primary"],
        timestamp=datetime.now()
    )
    
    for key, value in list(scan_results.items())[-10:]:
        count = len(value) if isinstance(value, list) else "N/A"
        embed.add_field(name=key, value=f"Items: `{count}`", inline=True)
    
    await interaction.response.send_message(embed=embed, view=MainMenuView())


async def export_results(interaction: discord.Interaction):
    """Export results to file"""
    if not scan_results:
        await interaction.response.send_message("📭 No results to export.", ephemeral=True)
        return
    
    filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join("results", filename)
    os.makedirs("results", exist_ok=True)
    
    with open(filepath, 'w') as f:
        json.dump(scan_results, f, indent=2, default=str)
    
    await interaction.response.send_message(
        f"✅ Results exported to `{filename}`",
        file=discord.File(filepath),
        view=MainMenuView()
    )


async def clear_results(interaction: discord.Interaction):
    """Clear all scan results"""
    global scan_results
    scan_results = {}
    await interaction.response.send_message("🗑️ All results cleared!", view=MainMenuView())


async def show_stats(interaction: discord.Interaction):
    """Show scanning statistics"""
    embed = discord.Embed(
        title="📈 Scanning Statistics",
        color=THEME_COLORS["primary"],
        timestamp=datetime.now()
    )
    
    total_scans = len(scan_results)
    total_items = sum(len(v) if isinstance(v, list) else 1 for v in scan_results.values())
    
    embed.add_field(name="Total Scans", value=f"`{total_scans}`", inline=True)
    embed.add_field(name="Total Items Found", value=f"`{total_items}`", inline=True)
    
    await interaction.response.send_message(embed=embed, view=MainMenuView())


# ============================================
# SUGGESTION FUNCTIONS
# ============================================

async def analyze_target_for_suggestions(interaction: discord.Interaction, target: str):
    """
    Analyze a target for technology detection and provide security suggestions.
    This is READ-ONLY - no active scanning or exploitation.
    """
    suggester = VulnerabilitySuggestions()
    httpx = HttpxTools()
    
    # Add protocol if missing
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'
    
    embed = discord.Embed(
        title="💡 Analyzing Target for Suggestions",
        description=f"Target: `{target}`",
        color=discord.Color.gold(),
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Detecting technologies...", inline=False)
    msg = await interaction.followup.send(embed=embed)
    
    try:
        # Get response data for analysis
        async with HttpxTools() as httpx:
            session = await httpx.get_session()
            async with session.get(target, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.text()
                headers = dict(resp.headers)
                cookies = [c.key for c in resp.cookies.values()]
        
        # Analyze and get suggestions
        result = await suggester.analyze_and_suggest(headers, body, cookies, target)
        
        detected_tech = result['detected_technologies']
        suggestions = result['suggestions']
        
        # Build response embed
        embed.color = discord.Color.blue()
        embed.clear_fields()
        
        # Show detected technologies
        if detected_tech:
            tech_list = ", ".join(detected_tech[:10])
            embed.add_field(
                name="🔍 Detected Technologies",
                value=f"```{tech_list}```",
                inline=False
            )
        else:
            embed.add_field(
                name="🔍 Technologies",
                value="```No specific technologies detected```",
                inline=False
            )
        
        # Add suggestions
        if suggestions:
            for suggestion in suggestions[:4]:  # Limit to 4 for embed size
                priority_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(suggestion.priority, "⚪")
                ideas = "\n".join(f"• {idea}" for idea in suggestion.manual_review_ideas[:4])
                embed.add_field(
                    name=f"{priority_emoji} {suggestion.technology}",
                    value=f"**{suggestion.category}**\n{ideas}",
                    inline=False
                )
        else:
            embed.add_field(
                name="Suggestions",
                value="No specific suggestions for detected technologies.",
                inline=False
            )
        
        # Add disclaimer
        embed.set_footer(text="⚠️ Manual testing ideas only. No exploitation performed. Follow program rules.")
        
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = discord.Color.red()
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        embed.add_field(
            name="💡 Tip",
            value="You can still select a technology from the menu to see general suggestions.",
            inline=False
        )
        await msg.edit(embed=embed, view=SuggestionsMenuView())


async def show_tech_suggestions(interaction: discord.Interaction, tech_key: str):
    """
    Show security suggestions for a specific technology.
    This provides informational guidance only - no active testing.
    """
    suggester = VulnerabilitySuggestions()
    suggestion = suggester.get_suggestion_by_tech(tech_key)
    
    if not suggestion:
        await interaction.response.send_message(
            f"❌ No suggestions found for: {tech_key}",
            ephemeral=True
        )
        return
    
    priority_emoji = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(suggestion.priority, "⚪")
    
    embed = discord.Embed(
        title=f"🔎 Manual Security Testing Suggestions",
        description=f"**Technology:** {suggestion.technology}\n**Category:** {suggestion.category}",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    embed.add_field(
        name=f"{priority_emoji} Priority Level",
        value=suggestion.priority,
        inline=True
    )
    
    embed.add_field(
        name="📝 Why It Matters",
        value=suggestion.why_it_matters,
        inline=False
    )
    
    # Add manual review ideas
    ideas_text = "\n".join(f"• {idea}" for idea in suggestion.manual_review_ideas)
    embed.add_field(
        name="📖 Manual Review Ideas",
        value=ideas_text,
        inline=False
    )
    
    # Add disclaimer
    embed.add_field(
        name="⚠️ Disclaimer",
        value=(
            "These are manual testing ideas based on common patterns.\n"
            "No exploitation or automated testing has been performed.\n"
            "Always follow program scope and responsible disclosure."
        ),
        inline=False
    )
    
    embed.set_footer(text="Bug Bounty Bot | Advisory Only - No Active Scanning")
    
    await interaction.response.send_message(embed=embed, view=SuggestionsMenuView())


# ============================================
# ADVANCED TOOLS PROCESSING
# ============================================

async def process_advanced_tools(interaction: discord.Interaction, action: str, domain: str):
    """Process advanced tools actions"""
    async with AdvancedTools() as tools:
        embed = discord.Embed(
            title=f"🚀 Running: {action.replace('_', ' ').title()}",
            description=f"Target: `{domain}`",
            color=THEME_COLORS["warning"],
            timestamp=datetime.now()
        )
        embed.add_field(name="Status", value="⏳ Processing...", inline=False)
        msg = await interaction.followup.send(embed=embed)
    
    try:
        if action == "dirbust":
            results = await tools.directory_bruteforce(domain)
        elif action == "takeover":
            results = await tools.check_subdomain_takeover([domain])
        elif action == "waf":
            results = await tools.detect_waf(domain)
        elif action == "cms":
            results = await tools.detect_cms(domain)
        elif action == "robots":
            results = await tools.analyze_robots_txt(domain)
        elif action == "sitemap":
            results = await tools.parse_sitemap(domain)
        elif action == "methods":
            results = await tools.check_http_methods(domain)
        elif action == "headers_full":
            results = await tools.full_header_analysis(domain)
        elif action == "favicon":
            results = await tools.get_favicon_hash(domain)
        else:
            results = {"error": "Unknown action"}
        
        embed.color = THEME_COLORS["primary"]
        embed.clear_fields()
        
        # Format results based on action
        if action == "dirbust":
            found = results.get('found', [])
            if found:
                paths = "\n".join([f"{f['path']} [{f['status']}]" for f in found[:15]])
                embed.add_field(name="✅ Found Paths", value=f"```\n{paths}\n```", inline=False)
            forbidden = results.get('forbidden', [])
            if forbidden:
                forb_paths = "\n".join([f['path'] for f in forbidden[:10]])
                embed.add_field(name="🚫 Forbidden (403)", value=f"```{forb_paths}```", inline=False)
            embed.add_field(name="Total Checked", value=f"`{results.get('total_checked', 0)}`", inline=True)
        
        elif action == "waf":
            waf_detected = results.get('waf_detected', False)
            embed.add_field(name="WAF Detected", value=f"`{'✅ Yes' if waf_detected else '❌ No'}`", inline=True)
            if waf_detected:
                embed.color = THEME_COLORS["danger"]
                embed.add_field(name="WAF Name", value=f"`{results.get('waf_name', 'Unknown')}`", inline=True)
                embed.add_field(name="Confidence", value=f"`{results.get('confidence', 'low')}`", inline=True)
        
        elif action == "cms":
            cms = results.get('cms_detected')
            embed.add_field(name="CMS", value=f"`{cms or 'Not detected'}`", inline=True)
            if results.get('version'):
                embed.add_field(name="Version", value=f"`{results.get('version')}`", inline=True)
            embed.add_field(name="Confidence", value=f"`{results.get('confidence', 'low')}`", inline=True)
        
        elif action == "takeover":
            vuln = results.get('vulnerable', [])
            if vuln:
                embed.color = THEME_COLORS["danger"]
                for v in vuln[:5]:
                    embed.add_field(
                        name=f"⚠️ {v['subdomain']}",
                        value=f"Service: {v.get('service', 'Unknown')}\nReason: {v.get('reason', 'N/A')}",
                        inline=False
                    )
            else:
                embed.add_field(name="Status", value="✅ No takeover vulnerabilities found", inline=False)
        
        elif action == "headers_full":
            embed.add_field(name="Grade", value=f"`{results.get('grade', 'N/A')}`", inline=True)
            embed.add_field(name="Score", value=f"`{results.get('score', 0)}/100`", inline=True)
            missing = results.get('missing', [])
            if missing:
                embed.add_field(name="Missing Headers", value=f"```{', '.join(missing[:5])}```", inline=False)
        
        else:
            # Generic display
            result_text = json.dumps(results, indent=2, default=str)[:1800]
            embed.add_field(name="✅ Results", value=f"```json\n{result_text}\n```", inline=False)
        
        scan_results[f"advanced_{action}_{domain}"] = results
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = THEME_COLORS["danger"]
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed, view=AdvancedMenuView())


async def process_cloud_tools(interaction: discord.Interaction, action: str, domain: str):
    """Process cloud and secrets tools actions"""
    async with CloudSecrets() as cloud:
        embed = discord.Embed(
            title=f"☁️ Running: {action.replace('_', ' ').title()}",
            description=f"Target: `{domain}`",
            color=THEME_COLORS["warning"],
            timestamp=datetime.now()
        )
        embed.add_field(name="Status", value="⏳ Processing...", inline=False)
        msg = await interaction.followup.send(embed=embed)
        
        try:
            if action == "s3":
                results = await cloud.enumerate_s3_buckets(domain)
            elif action == "azure":
                results = await cloud.enumerate_azure_blobs(domain)
            elif action == "gcp":
                results = await cloud.enumerate_gcp_buckets(domain)
            elif action == "secrets":
                url = f"https://{domain}" if not domain.startswith('http') else domain
                results = await cloud.scan_for_secrets(url)
            elif action == "github_dorks":
                results = cloud.generate_github_dorks(domain)
            elif action == "google_dorks":
                results = cloud.generate_google_dorks(domain)
            elif action == "shodan_dorks":
                results = cloud.generate_shodan_dorks(domain)
            elif action == "emails":
                results = await cloud.harvest_emails(domain)
            elif action == "firebase":
                results = await cloud.check_firebase(domain.replace('.', '-').replace('.com', ''))
            else:
                results = {"error": "Unknown action"}
            
            embed.color = THEME_COLORS["primary"]
            embed.clear_fields()
            
            # Format based on action
            if action in ["s3", "azure", "gcp"]:
                public = results.get('public_buckets', []) or results.get('public_containers', [])
                if public:
                    embed.color = THEME_COLORS["danger"]
                    bucket_list = "\n".join([b.get('url', b.get('name', ''))[:60] for b in public[:10]])
                    embed.add_field(name="⚠️ Public Buckets Found!", value=f"```\n{bucket_list}\n```", inline=False)
                else:
                    embed.add_field(name="Status", value="✅ No public buckets found", inline=False)
                embed.add_field(name="Checked", value=f"`{results.get('total_checked', 0)}`", inline=True)
            
            elif action == "secrets":
                secrets = results.get('secrets_found', [])
                if secrets:
                    embed.color = THEME_COLORS["danger"]
                    secret_list = "\n".join([f"{s['type']}: {s['value']}" for s in secrets[:10]])
                    embed.add_field(name="⚠️ Secrets Found!", value=f"```\n{secret_list}\n```", inline=False)
                    embed.add_field(name="Risk Level", value=f"`{results.get('risk_level', 'unknown')}`", inline=True)
                else:
                    embed.add_field(name="Status", value="✅ No secrets detected", inline=False)
            
            elif action in ["github_dorks", "google_dorks", "shodan_dorks"]:
                dorks = results.get('dorks', [])[:12] # Limit to 12 links per embed to avoid huge messages
                
                # Format as clickable links: [Query](URL)
                dork_links = []
                for d in dorks:
                    # Clean up query for display
                    display_query = d['query'][:40] + "..." if len(d['query']) > 40 else d['query']
                    dork_links.append(f"• [{display_query}]({d['url']})")
                
                # Split into columns if many
                chunk_size = 6
                chunks = [dork_links[i:i + chunk_size] for i in range(0, len(dork_links), chunk_size)]
                
                for i, chunk in enumerate(chunks):
                    embed.add_field(name=f"🔍 Recommended Dorks {i+1}", value="\n".join(chunk), inline=True)
                
                embed.add_field(name="Total Generated", value=f"`{results.get('total', 0)}`", inline=False)
                embed.set_footer(text="Click links to open search directly")
            
            elif action == "emails":
                emails = results.get('emails', [])
                if emails:
                    email_list = "\n".join(emails[:15])
                    embed.add_field(name="📧 Found Emails", value=f"```\n{email_list}\n```", inline=False)
                patterns = results.get('common_patterns', [])[:5]
                embed.add_field(name="Common Patterns", value=f"```{chr(10).join(patterns)}```", inline=False)
            
            elif action == "firebase":
                if results.get('vulnerable'):
                    embed.color = THEME_COLORS["danger"]
                    embed.add_field(name="⚠️ VULNERABLE!", value="Firebase database is publicly accessible!", inline=False)
                else:
                    embed.add_field(name="Status", value="✅ No exposed Firebase databases found", inline=False)
            
            else:
                result_text = json.dumps(results, indent=2, default=str)[:1800]
                embed.add_field(name="✅ Results", value=f"```json\n{result_text}\n```", inline=False)
            
            scan_results[f"cloud_{action}_{domain}"] = results
            await msg.edit(embed=embed, view=MainMenuView())
            
        except Exception as e:
            embed.color = THEME_COLORS["danger"]
            embed.clear_fields()
            embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
            await msg.edit(embed=embed, view=CloudMenuView())
        



async def process_network_tools(interaction: discord.Interaction, action: str, domain: str):
    """Process network and SSL analysis tools"""
    async with NetworkAnalysis() as network:
        embed = discord.Embed(
            title=f"🔐 Running: {action.replace('_', ' ').title()}",
            description=f"Target: `{domain}`",
            color=discord.Color.teal(),
            timestamp=datetime.now()
        )
        embed.add_field(name="Status", value="⏳ Analyzing...", inline=False)
        msg = await interaction.followup.send(embed=embed)
    
    try:
        if action == "ssl":
            results = await network.analyze_ssl_certificate(domain)
        elif action == "ssl_vuln":
            results = await network.check_ssl_vulnerabilities(domain)
        elif action == "asn":
            results = await network.asn_lookup(domain)
        elif action == "cdn":
            results = await network.detect_cdn(domain)
        elif action == "zone_transfer":
            results = await network.check_zone_transfer(domain)
        elif action == "reverse_dns":
            import socket
            ip = socket.gethostbyname(domain) if not domain.replace('.','').isdigit() else domain
            results = await network.reverse_dns(ip)
        elif action == "alive":
            results = await network.check_host_alive([domain])
        elif action == "whois_full":
            results = await network.enhanced_whois(domain)
        else:
            results = {"error": "Unknown action"}
        
        embed.color = discord.Color.green()
        embed.clear_fields()
        
        # Format based on action
        if action == "ssl":
            embed.add_field(name="SSL Enabled", value=f"`{'✅ Yes' if results.get('ssl_enabled') else '❌ No'}`", inline=True)
            embed.add_field(name="TLS Version", value=f"`{results.get('tls_version', 'N/A')}`", inline=True)
            embed.add_field(name="Grade", value=f"`{results.get('grade', 'N/A')}`", inline=True)
            cert = results.get('certificate', {})
            if cert:
                subject = cert.get('subject', {})
                embed.add_field(name="Subject", value=f"`{subject.get('commonName', 'N/A')}`", inline=True)
                embed.add_field(name="Expires In", value=f"`{cert.get('days_until_expiry', 'N/A')} days`", inline=True)
            vulns = results.get('vulnerabilities', [])
            if vulns:
                embed.color = discord.Color.red()
                embed.add_field(name="⚠️ Vulnerabilities", value=f"```{chr(10).join(vulns[:5])}```", inline=False)
        
        elif action == "asn":
            embed.add_field(name="IP", value=f"`{results.get('ip', 'N/A')}`", inline=True)
            embed.add_field(name="ASN", value=f"`{results.get('asn', 'N/A')}`", inline=True)
            embed.add_field(name="Organization", value=f"`{results.get('asn_name', 'N/A')[:50]}`", inline=True)
            ranges = results.get('related_ranges', [])[:5]
            if ranges:
                embed.add_field(name="IP Ranges", value=f"```{chr(10).join(ranges)}```", inline=False)
        
        elif action == "cdn":
            cdn_detected = results.get('cdn_detected', False)
            embed.add_field(name="CDN Detected", value=f"`{'✅ Yes' if cdn_detected else '❌ No'}`", inline=True)
            if cdn_detected:
                embed.add_field(name="CDN Name", value=f"`{results.get('cdn_name', 'Unknown')}`", inline=True)
            ips = results.get('ips', [])
            if ips:
                embed.add_field(name="IPs", value=f"```{', '.join(ips[:5])}```", inline=False)
        
        elif action == "zone_transfer":
            if results.get('vulnerable'):
                embed.color = discord.Color.red()
                embed.add_field(name="⚠️ VULNERABLE!", value="DNS Zone Transfer is enabled!", inline=False)
                records = results.get('records', [])[:10]
                if records:
                    rec_text = "\n".join([f"{r['name']} {r['type']} {r['value']}" for r in records])
                    embed.add_field(name="Records", value=f"```{rec_text[:500]}```", inline=False)
            else:
                embed.add_field(name="Status", value="✅ Zone transfer not allowed", inline=False)
        
        elif action == "whois_full":
            embed.add_field(name="Registrar", value=f"`{results.get('registrar', 'N/A')[:50]}`", inline=True)
            embed.add_field(name="Created", value=f"`{results.get('creation_date', 'N/A')[:20]}`", inline=True)
            embed.add_field(name="Expires", value=f"`{results.get('expiration_date', 'N/A')[:20]}`", inline=True)
            ns = results.get('nameservers', [])[:4]
            if ns:
                embed.add_field(name="Nameservers", value=f"```{chr(10).join(ns)}```", inline=False)
        
        else:
            result_text = json.dumps(results, indent=2, default=str)[:1800]
            embed.add_field(name="✅ Results", value=f"```json\n{result_text}\n```", inline=False)
        
        scan_results[f"network_{action}_{domain}"] = results
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = discord.Color.red()
        embed.clear_fields()
        embed.add_field(name="❌ Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed, view=NetworkMenuView())


# ============================================
# BOT COMMANDS
# ============================================

@bot.event
async def on_ready():
    print(f'🤖 {bot.user} is online!')
    print(f'📊 Connected to {len(bot.guilds)} servers')
    try:
        synced = await bot.tree.sync()
        print(f'✅ Synced {len(synced)} slash commands')
    except Exception as e:
        print(f'❌ Error syncing commands: {e}')
    
    # Initialize auto-scan manager after bot is ready
    from modules.auto_scan import initialize_auto_scan_manager
    initialize_auto_scan_manager(scope_manager)
    print('🔄 Auto-scan manager initialized')


@bot.tree.command(name="bugbounty", description="Open the Bug Bounty Tools menu")
async def bugbounty(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🎯 Bug Bounty Toolkit",
        description="Select a tool category from the dropdown menu below",
        color=discord.Color.blue()
    )
    embed.add_field(name="🔍 Reconnaissance", value="Subdomain enum, live domains, DNS, WHOIS", inline=True)
    embed.add_field(name="🌐 HTTPX Analysis", value="HTTP probing, tech detection, screenshots", inline=True)
    embed.add_field(name="⚡ Vulnerability Scans", value="XSS, SQLi, LFI, SSRF, CORS", inline=True)
    embed.add_field(name="📋 Domain Filters", value="Find login, signup, admin pages", inline=True)
    embed.add_field(name="🔗 URL Analysis", value="Wayback, JS files, endpoints", inline=True)
    embed.add_field(name="📊 Results", value="View, export, and manage results", inline=True)
    embed.set_footer(text="Select an option from the dropdown below")
    
    await interaction.response.send_message(embed=embed, view=MainMenuView())


@bot.tree.command(name="scan", description="Quick scan a domain")
@app_commands.describe(domain="Target domain to scan")
async def quick_scan(interaction: discord.Interaction, domain: str):
    await interaction.response.defer()
    
    domain = ScopeManager.normalize_domain(domain)
    
    embed = discord.Embed(
        title=f"⚡ Quick Scan: {domain}",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Running quick scan...", inline=False)
    msg = await interaction.followup.send(embed=embed)
    
    try:
        # Run multiple checks
        async with HttpxTools() as httpx:
            live = await httpx.probe_domains([f"https://{domain}", f"http://{domain}"])
            tech = await httpx.detect_technology(domain)
        
        embed.color = discord.Color.green()
        embed.clear_fields()
        embed.add_field(name="Live Status", value=f"```{'✅ Online' if live else '❌ Offline'}```", inline=True)
        embed.add_field(name="Technologies", value=f"```{str(tech)[:200]}```", inline=False)
        
        await msg.edit(embed=embed, view=MainMenuView())
        
    except Exception as e:
        embed.color = discord.Color.red()
        embed.add_field(name="Error", value=f"```{str(e)}```", inline=False)
        await msg.edit(embed=embed)


@bot.tree.command(name="help", description="Show all available commands and features")
async def help_command(interaction: discord.Interaction):
    embed = discord.Embed(
        title="📚 Bug Bounty Bot Help",
        description="Complete guide to using the Bug Bounty Toolkit",
        color=discord.Color.green()
    )
    
    embed.add_field(
        name="🎯 Main Command",
        value="`/bugbounty` - Open the interactive tools menu",
        inline=False
    )
    embed.add_field(
        name="⚡ Quick Commands",
        value="`/scan <domain>` - Quick domain scan\n`/help` - Show this help message",
        inline=False
    )
    embed.add_field(
        name="🔍 Reconnaissance Tools",
        value="• Subdomain Enumeration\n• Live Domain Check\n• Port Scanning\n• DNS Records\n• WHOIS Lookup\n• Reverse IP",
        inline=True
    )
    embed.add_field(
        name="🌐 HTTPX Tools",
        value="• HTTP Probing\n• Technology Detection\n• Status Code Filter\n• Title Extraction\n• Content Length\n• Screenshots",
        inline=True
    )
    embed.add_field(
        name="⚡ Vulnerability Scanners",
        value="• XSS Scanner\n• SQL Injection\n• LFI/RFI\n• Open Redirect\n• SSRF Detection\n• CORS Check\n• Header Security",
        inline=True
    )
    embed.add_field(
        name="📋 Domain Filters",
        value="• Login Pages\n• Signup Pages\n• Admin Panels\n• API Endpoints\n• Forgot Password\n• Forms",
        inline=True
    )
    embed.add_field(
        name="🔗 URL Analysis",
        value="• Parameter Discovery\n• Wayback URLs\n• JS File Finder\n• Endpoint Extraction\n• Link Crawler\n• Secret Finder",
        inline=True
    )
    embed.add_field(
        name="🚀 Advanced Tools",
        value="• Directory Bruteforce\n• Subdomain Takeover\n• WAF Detection\n• CMS Detection\n• HTTP Methods\n• Favicon Hash",
        inline=True
    )
    embed.add_field(
        name="☁️ Cloud & Secrets",
        value="• S3/Azure/GCP Buckets\n• Secret Scanner\n• GitHub Dorks\n• Google Dorks\n• Email Harvester\n• Firebase Check",
        inline=True
    )
    embed.add_field(
        name="🔐 Network/SSL",
        value="• SSL Analysis\n• ASN Lookup\n• CDN Detection\n• Zone Transfer\n• Reverse DNS\n• Enhanced WHOIS",
        inline=True
    )
    embed.add_field(
        name="💡 Smart Suggestions",
        value="• Auto-detect Tech\n• Manual Testing Ideas\n• Security Advisories\n• No Active Scanning",
        inline=True
    )
    
    embed.set_footer(text="Use /bugbounty to access all tools via dropdown menu")
    
    await interaction.response.send_message(embed=embed)


# ============================================
# SCOPE MANAGEMENT COMMANDS
# ============================================

@bot.tree.command(name="addscope", description="Add a target domain to scope (creates channels automatically)")
@app_commands.describe(domain="Target domain to add to scope (e.g., example.com)")
@app_commands.default_permissions(manage_channels=True)
async def add_scope(interaction: discord.Interaction, domain: str):
    """Add a domain to scope and create all tracking channels"""
    await interaction.response.defer()
    await process_add_scope(interaction, domain)

async def process_add_scope(interaction: discord.Interaction, domain: str):
    """Process add scope request"""
    # Normalize first to show correct domain in UI
    domain = ScopeManager.normalize_domain(domain)
    
    embed = discord.Embed(
        title="🎯 Adding Target to Scope",
        description=f"Creating channels for `{domain}`...",
        color=discord.Color.blue()
    )
    msg = await interaction.followup.send(embed=embed)
    
    result = await scope_manager.add_target(
        guild=interaction.guild,
        domain=domain,
        added_by=interaction.user
    )
    
    if result["success"]:
        embed.color = discord.Color.green()
        embed.title = "✅ Target Added to Scope!"
        embed.description = f"Successfully created workspace for `{result['domain']}`"
        embed.clear_fields()
        
        category_name = result.get('category_name', 'Unknown')
        embed.add_field(name="Category", value=f"`{category_name}`", inline=True)
        embed.add_field(name="Channels Created", value=f"`{result['channels_created']}`", inline=True)
        
        # New consolidated channel list for success message
        embed.add_field(
            name="📁 Core Channels",
            value=(
                "• #subdomains - All discovered targets\n"
                "• #live-domains - Active hosts & ports\n"
                "• #endpoints - URLs, Params & JS\n"
                "• #security-findings - Vulns, Secrets, Cloud\n"
                "• #screenshots - Automated evidence\n"
                "• #reports - Final exports"
            ),
            inline=False
        )
        
        # Post channel-specific interactive views
        channels = result.get("channels", {})
        for channel_name, channel_id in channels.items():
            channel = interaction.guild.get_channel(channel_id)
            if channel:
                try:
                    view = create_channel_view(channel_name, domain)
                    await channel.send(
                        f"⚡ **{channel_name.replace('-', ' ').title()} Dashboard**\nUse the buttons below!",
                        view=view
                    )
                except:
                    pass
    else:
        embed.color = discord.Color.red()
        embed.title = "❌ Failed to Add Scope"
        embed.description = result.get("error", "Unknown error")
    
    await msg.edit(embed=embed)


@bot.tree.command(name="removescope", description="Remove a target from scope")
@app_commands.describe(
    domain="Target domain to remove",
    delete_channels="Also delete all channels (default: False)"
)
@app_commands.default_permissions(manage_channels=True)
async def remove_scope(interaction: discord.Interaction, domain: str, delete_channels: bool = False):
    """Remove a domain from scope"""
    await interaction.response.defer()
    await process_remove_scope(interaction, domain, delete_channels)

async def process_remove_scope(interaction: discord.Interaction, domain: str, delete_channels: bool = False):
    """Process remove scope request"""
    domain = ScopeManager.normalize_domain(domain)
    
    result = await scope_manager.remove_target(
        guild=interaction.guild,
        domain=domain,
        delete_channels=delete_channels
    )
    
    if result["success"]:
        embed = discord.Embed(
            title="✅ Scope Removed",
            description=f"Removed `{result['domain']}` from scope",
            color=discord.Color.green()
        )
        if delete_channels:
            embed.add_field(name="Channels", value="All channels deleted", inline=True)
    else:
        embed = discord.Embed(
            title="❌ Error",
            description=result.get("error", "Unknown error"),
            color=discord.Color.red()
        )
    
    await interaction.followup.send(embed=embed)


@bot.tree.command(name="listscopes", description="List all targets in scope")
async def list_scopes(interaction: discord.Interaction):
    """List all domains in scope for this server"""
    await process_list_scopes(interaction)

async def process_list_scopes(interaction: discord.Interaction):
    """Process list scopes logic"""
    scopes = scope_manager.get_guild_scopes(interaction.guild.id)
    
    embed = discord.Embed(
        title="🎯 Targets in Scope",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    if scopes:
        for scope in scopes:
            status_emoji = "🟢" if scope.status == "active" else "🟡"
            embed.add_field(
                name=f"{status_emoji} {scope.domain}",
                value=f"Added: {scope.added_at[:10]}\nChannels: {len(scope.channels)}",
                inline=True
            )
        embed.set_footer(text=f"Total: {len(scopes)} targets")
    else:
        embed.description = "No targets in scope. Use `/addscope <domain>` to add one!"
    
    # Check if interaction already responded/deferred
    try:
        if interaction.response.is_done():
            await interaction.followup.send(embed=embed)
        else:
            await interaction.response.send_message(embed=embed)
    except:
        await interaction.channel.send(embed=embed)


@bot.tree.command(name="fullscan", description="Run a complete scan on a scoped target")
@app_commands.describe(domain="Target domain to scan (must be in scope)")
async def full_scan_scope(interaction: discord.Interaction, domain: str):
    """Run comprehensive scan and post results to appropriate channels"""
    await interaction.response.defer()
    await process_full_scan(interaction, domain)

async def process_full_scan(interaction: discord.Interaction, domain: str):
    """Process full scan logic"""
    # Normalize domain
    domain = ScopeManager.normalize_domain(domain)
    
    # Check if domain is in scope
    scope = scope_manager.get_scope(interaction.guild.id, domain)
    if not scope:
        embed = discord.Embed(
            title="❌ Domain Not in Scope",
            description=f"`{domain}` is not in scope. Add it first with `/addscope {domain}`",
            color=discord.Color.red()
        )
        if interaction.response.is_done():
            await interaction.followup.send(embed=embed)
        else:
            await interaction.response.send_message(embed=embed)
        return
    
    embed = discord.Embed(
        title=f"🚀 Full Scan: {domain}",
        description="Running comprehensive reconnaissance...",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    embed.add_field(name="Status", value="⏳ Initializing...", inline=False)
    
    if interaction.response.is_done():
        msg = await interaction.followup.send(embed=embed)
    else:
        await interaction.response.send_message(embed=embed)
        msg = await interaction.original_response()
    
    async with ReconTools() as recon, HttpxTools() as httpx_tool, AdvancedTools() as advanced_tool:
        guild = interaction.guild
        results_summary = []
        
        try:
            # 1. Subdomain Enumeration
            embed.set_field_at(0, name="Status", value="🌐 Enumerating subdomains...", inline=False)
            await msg.edit(embed=embed)
            
            subdomains = await recon.subdomain_enum(domain)
            if subdomains:
                await scope_manager.post_subdomains(guild, domain, subdomains, "Full Scan")
                results_summary.append(f"🌐 Subdomains: {len(subdomains)}")
            else:
                results_summary.append("🌐 Subdomains: 0 (or API failed)")
            
            # 2. Live Domain Check
            embed.set_field_at(0, name="Status", value="✅ Checking live domains...", inline=False)
            await msg.edit(embed=embed)
            
            # Always check the main domain + any found subdomains
            targets_to_check = subdomains + [domain] if subdomains else [domain]
            unique_targets = list(set(targets_to_check))
            
            live_domains = await httpx_tool.probe_domains(unique_targets[:100])
            
            if live_domains:
                await scope_manager.post_live_domains(guild, domain, live_domains, "Full Scan")
                results_summary.append(f"✅ Live Domains: {len(live_domains)}")
                
                # Capture Screenshots for up to 20 domains
                embed.set_field_at(0, name="Status", value="📸 Capturing screenshots...", inline=False)
                await msg.edit(embed=embed)
                
                import modules.screenshot_utils as ss_utils
                
                # If no live domains, try main domain anyway
                domains_to_capture = live_domains[:20] if live_domains else [f"https://{domain}"]
                
                count = 0
                for vid_domain in domains_to_capture:
                    count += 1
                    file = await ss_utils.capture_screenshot(vid_domain, f"screen_{count}.png")
                    if file:
                        embed_ss = discord.Embed(title=f"📸 Screenshot: {vid_domain}", color=discord.Color.dark_theme())
                        embed_ss.set_image(url=f"attachment://screen_{count}.png")
                        await scope_manager.post_to_channel(guild, domain, "screenshots", embed=embed_ss, file=file)
                
                results_summary.append(f"📸 Screenshots: {count} captured")
            else:
                 results_summary.append("✅ Live Domains: 0")
            
            # 3. Technology Detection
            embed.set_field_at(0, name="Status", value="🔧 Detecting technologies...", inline=False)
            await msg.edit(embed=embed)
            
            tech = await httpx_tool.detect_technology(domain)
            if tech:
                await scope_manager.post_technology(guild, domain, tech, "Full Scan")
                results_summary.append(f"🔧 Technologies: {len(tech.get('technologies', []))}")
            
            # 4. Port Scanning
            embed.set_field_at(0, name="Status", value="🔌 Scanning ports...", inline=False)
            await msg.edit(embed=embed)
            
            ports = await recon.port_scan(domain)
            if ports:
                await scope_manager.post_ports(guild, domain, ports, "Full Scan")
                results_summary.append(f"🔌 Open Ports: {len(ports.get('open_ports', []))}")
            
            # 5. DNS Records
            embed.set_field_at(0, name="Status", value="📝 Getting DNS records...", inline=False)
            await msg.edit(embed=embed)
            
            dns = await recon.dns_records(domain)
            if dns:
                await scope_manager.post_dns(guild, domain, dns, "Full Scan")
                results_summary.append("📝 DNS Records: Retrieved")
            
            # 6. Wayback URLs & Parameters
            embed.set_field_at(0, name="Status", value="📜 Fetching Wayback URLs...", inline=False)
            await msg.edit(embed=embed)
            
            wayback = await recon.wayback_urls(domain)
            if wayback:
                results_summary.append(f"📜 Wayback URLs: {len(wayback)}")
            
            params = await recon.find_parameters(domain)
            if params:
                await scope_manager.post_parameters(guild, domain, params, "Wayback")
                results_summary.append(f"❓ Parameters: {len(params)}")
            
            # 7. JS Files
            embed.set_field_at(0, name="Status", value="📄 Finding JS files...", inline=False)
            await msg.edit(embed=embed)
            
            js_files = await recon.find_js_files(domain)
            if js_files:
                view = JSFileView(js_files, domain)
                await scope_manager.post_js_files(guild, domain, js_files, "Full Scan", view=view)
                results_summary.append(f"📄 JS Files: {len(js_files)}")
            
            # 8. Endpoints
            embed.set_field_at(0, name="Status", value="🔗 Extracting endpoints...", inline=False)
            await msg.edit(embed=embed)
            
            endpoints = await recon.extract_endpoints(domain)
            if endpoints:
                await scope_manager.post_endpoints(guild, domain, endpoints, "Full Scan")
                results_summary.append(f"🔗 Endpoints: {len(endpoints)}")
            
            # 9. Robots.txt
            embed.set_field_at(0, name="Status", value="🤖 Checking robots.txt...", inline=False)
            await msg.edit(embed=embed)
            
            robots = await advanced_tool.analyze_robots_txt(domain)
            if robots.get('found'):
                interesting = robots.get('interesting_paths', [])
                if interesting:
                    await scope_manager.post_endpoints(guild, domain, interesting, "robots.txt")
                results_summary.append(f"🤖 Robots.txt: Found")
                
            # 10. Smart AI Analysis (New Step)
            embed.set_field_at(0, name="Status", value="🧠 Running Smart Analysis...", inline=False)
            await msg.edit(embed=embed)
            
            from modules.vuln_analysis import SmartAnalyzer
            analyzer = SmartAnalyzer()
            
            # Analyze Tech Stack
            tech_findings = analyzer.analyze_tech_stack(tech.get('technologies', []))
            for finding in tech_findings:
                await scope_manager.post_finding(
                    guild, domain, finding['title'], finding['description'],
                    finding['severity'], "SmartAnalyzer", 
                    procedure=finding.get('procedure')
                )
                
            # Analyze URLs
            all_urls = (subdomains or []) + (endpoints or []) + (wayback or [])
            url_findings = analyzer.analyze_urls(all_urls[:500]) # Limit for performance
            for finding in url_findings:
                 await scope_manager.post_finding(
                    guild, domain, finding['title'], finding['description'],
                    finding['severity'], "SmartAnalyzer",
                    procedure=finding.get('procedure')
                )
            
            # Smart JS Analysis
            js_findings = analyzer.analyze_js_files_smart(js_files or [])
            for finding in js_findings:
                await scope_manager.post_finding(
                    guild, domain, finding['title'], finding['description'],
                    finding['severity'], "SmartAnalyzer",
                    procedure=finding.get('procedure')
                )
                
            # Generate AI Summary
            scan_data = {
                'technologies': tech.get('technologies', []), 
                'vulns': tech_findings + url_findings + js_findings
            }
            ai_report = analyzer.generate_ai_report(domain, scan_data)
            
            # Post report to security channel
            await scope_manager.post_finding(
                guild, domain, "🧠 AI Strategic Assessment", ai_report, "Info", "SmartAnalyzer"
            )
            results_summary.append("🧠 Smart Analysis: Complete")
            
            # Final Summary
            embed.color = discord.Color.green()
            embed.title = f"✅ Full Scan Complete: {domain}"
            embed.description = "All results have been posted to the appropriate channels!"
            embed.clear_fields()
            
            summary_text = "\n".join(results_summary) if results_summary else "No data found"
            embed.add_field(name="📊 Summary", value=f"```\n{summary_text}\n```", inline=False)
            embed.add_field(
                name="📁 Check Channels",
                value="Results are organized in:\n• #subdomains\n• #live-domains\n• #endpoints\n• #technologies\nand more!",
                inline=False
            )
            
            await msg.edit(embed=embed)
            
        except Exception as e:
            embed.color = discord.Color.red()
            embed.title = "❌ Scan Error"
            embed.description = f"```{str(e)}```"
            await msg.edit(embed=embed)


@bot.tree.command(name="note", description="Add a note to a target's notes channel")
@app_commands.describe(
    domain="Target domain",
    note="Your note text"
)
async def add_note(interaction: discord.Interaction, domain: str, note: str):
    """Add a note to a scoped target"""
    await process_add_note(interaction, domain, note)

async def process_add_note(interaction: discord.Interaction, domain: str, note: str):
    """Process add note request"""
    domain = ScopeManager.normalize_domain(domain)
    
    scope = scope_manager.get_scope(interaction.guild.id, domain)
    if not scope:
        if interaction.response.is_done():
            await interaction.followup.send(
                f"❌ `{domain}` is not in scope!", ephemeral=True
            )
        else:
            await interaction.response.send_message(
                f"❌ `{domain}` is not in scope!", ephemeral=True
            )
        return
    
    await scope_manager.post_note(interaction.guild, domain, note, interaction.user)
    
    if interaction.response.is_done():
        await interaction.followup.send(
            f"✅ Note added to {domain}'s notes channel!", ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"✅ Note added to {domain}'s notes channel!", ephemeral=True
        )

@bot.tree.command(name="quicksub", description="Run a quick subdomain scan")
@app_commands.describe(domain="Target domain", limit="Max results (default 100)")
async def quick_sub(interaction: discord.Interaction, domain: str, limit: int = 100):
    await process_quick_sub(interaction, domain, limit)

async def process_quick_sub(interaction: discord.Interaction, domain: str, limit: int = 100):
    """Process quick subdomain scan"""
    domain = ScopeManager.normalize_domain(domain)
    
    embed = discord.Embed(
        title=f"🌐 Quick Subdomains: {domain}",
        description="Scanning...",
        color=discord.Color.blue()
    )
    if interaction.response.is_done():
        msg = await interaction.followup.send(embed=embed)
    else:
        await interaction.response.send_message(embed=embed)
        msg = await interaction.original_response()
    
    try:
        async with ReconTools() as recon:
            subs = await recon.subdomain_enum(domain)
            
            embed.color = discord.Color.green()
            embed.description = f"Found `{len(subs)}` subdomains"
            
            limit = int(limit) if limit else 100
            display_subs = subs[:limit]
            
            chunk = "\n".join(display_subs[:40])
            if len(display_subs) > 40:
                chunk += f"\n... and {len(display_subs) - 40} more"
                
            embed.add_field(name="Results", value=f"```\n{chunk}\n```", inline=False)
            await msg.edit(embed=embed)
        
    except Exception as e:
        embed.color = discord.Color.red()
        embed.description = f"Error: {str(e)}"
        await msg.edit(embed=embed)

@bot.tree.command(name="quicklive", description="Quickly check live domains")
@app_commands.describe(domain="Target domain", limit="Max to check (default 100)")
async def quick_live(interaction: discord.Interaction, domain: str, limit: int = 100):
    await process_quick_live(interaction, domain, limit)

async def process_quick_live(interaction: discord.Interaction, domain: str, limit: int = 100):
    """Process quick live check"""
    domain = ScopeManager.normalize_domain(domain)
    
    embed = discord.Embed(
        title=f"✅ Quick Live Check: {domain}",
        description="Enumerating and probing...",
        color=discord.Color.blue()
    )
    if interaction.response.is_done():
        msg = await interaction.followup.send(embed=embed)
    else:
        await interaction.response.send_message(embed=embed)
        msg = await interaction.original_response()
        
    try:
        async with ReconTools() as recon, HttpxTools() as httpx:
            subs = await recon.subdomain_enum(domain)
            
            limit = int(limit) if limit else 100
            subs_to_check = subs[:limit]
            
            embed.description = f"Probing {len(subs_to_check)} domains..."
            await msg.edit(embed=embed)
            
            live = await httpx.probe_domains(subs_to_check)
            
            embed.color = discord.Color.green()
            embed.description = f"Found `{len(live)}` live domains"
            
            chunk = "\n".join(live[:40])
            if len(live) > 40:
                chunk += f"\n... and {len(live) - 40} more"
                
            embed.add_field(name="Live Results", value=f"```\n{chunk}\n```", inline=False)
            await msg.edit(embed=embed)
        
    except Exception as e:
        embed.color = discord.Color.red()
        embed.description = f"Error: {str(e)}"
        await msg.edit(embed=embed)


# ============================================
# AUTO-SCAN COMMANDS
# ============================================

@bot.tree.command(name="autoscan", description="Create an automated scan for a scoped domain")
@app_commands.describe(
    domain="Target domain (must be in scope)",
    scan_type="Type of scan to run",
    interval_minutes="How often to run the scan (default: 60)"
)
@app_commands.choices(scan_type=[
    app_commands.Choice(name="Full Recon", value="full"),
    app_commands.Choice(name="Subdomain Scan", value="subdomain"),
    app_commands.Choice(name="Live Domain Check", value="live"),
    app_commands.Choice(name="Technology Detection", value="tech"),
    app_commands.Choice(name="Vulnerability Check", value="vuln"),
])
async def auto_scan(interaction: discord.Interaction, domain: str, scan_type: str, interval_minutes: int = 60):
    """Create an automated scan task for a scoped domain"""
    await interaction.response.defer()
    
    scope = scope_manager.get_scope(interaction.guild.id, domain)
    if not scope:
        embed = discord.Embed(
            title="❌ Domain Not in Scope",
            description=f"`{domain}` is not in scope. Add it first with `/addscope {domain}`",
            color=discord.Color.red()
        )
        await interaction.followup.send(embed=embed)
        return
    
    # Get the subdomains channel for notifications
    channel_id = scope_manager.get_channel_id(interaction.guild.id, domain, "subdomains")
    if not channel_id:
        channel_id = interaction.channel.id  # Fallback to current channel
    
    try:
        task_id = await auto_scan_manager.create_scan_task(
            domain=domain,
            guild_id=interaction.guild.id,
            channel_id=channel_id,
            scan_type=scan_type,
            interval_minutes=interval_minutes
        )
        
        embed = discord.Embed(
            title="✅ Auto-Scan Created!",
            description=f"Created scheduled {scan_type} scan for `{domain}`",
            color=discord.Color.green()
        )
        embed.add_field(name="Task ID", value=f"`{task_id}`", inline=True)
        embed.add_field(name="Interval", value=f"Every {interval_minutes} minutes", inline=True)
        embed.add_field(name="Next Run", value=f"<t:{int((datetime.now() + timedelta(minutes=interval_minutes)).timestamp())}:R>", inline=True)
        
        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        embed = discord.Embed(
            title="❌ Error Creating Auto-Scan",
            description=f"{str(e)}",
            color=discord.Color.red()
        )
        await interaction.followup.send(embed=embed)


@bot.tree.command(name="listautoscans", description="List all automated scans for this server")
async def list_auto_scans(interaction: discord.Interaction):
    """List all automated scan tasks for the guild"""
    await process_list_auto_scans(interaction)

async def process_list_auto_scans(interaction: discord.Interaction):
    """Process list automated scans logic"""
    tasks = await auto_scan_manager.list_tasks_for_guild(interaction.guild.id)
    
    embed = discord.Embed(
        title="🔄 Active Auto-Scans",
        color=THEME_COLORS["info"],
        timestamp=datetime.now()
    )
    
    if tasks:
        for task in tasks[:10]:  # Limit to first 10
            status_emoji = "🟢" if task.enabled else "🔴"
            embed.add_field(
                name=f"{status_emoji} {task.domain} ({task.scan_type})",
                value=f"ID: `{task.id}`\nInterval: {task.interval_minutes}min\nNext: <t:{int(task.next_run.timestamp())}:R>",
                inline=False
            )
        embed.set_footer(text=f"Showing {len(tasks)} tasks (max 10)")
    else:
        embed.description = "No auto-scans configured. Use `/autoscan` to create one!"
    
    if interaction.response.is_done():
        await interaction.followup.send(embed=embed)
    else:
        await interaction.response.send_message(embed=embed)


@bot.tree.command(name="stopautoscan", description="Stop an automated scan")
@app_commands.describe(task_id="ID of the auto-scan task to stop")
async def stop_auto_scan(interaction: discord.Interaction, task_id: str):
    """Stop an automated scan task"""
    if task_id in auto_scan_manager.scan_tasks:
        await auto_scan_manager.disable_task(task_id)
        embed = discord.Embed(
            title="✅ Auto-Scan Stopped",
            description=f"Auto-scan `{task_id}` has been disabled",
            color=discord.Color.green()
        )
    else:
        embed = discord.Embed(
            title="❌ Task Not Found",
            description=f"No auto-scan with ID `{task_id}` found",
            color=discord.Color.red()
        )
    
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="analyze_js", description="Analyze JavaScript for secrets, endpoints, and variables")
@app_commands.describe(
    url="URL to a JS file to analyze",
    code="Raw JavaScript code to analyze"
)
async def analyze_js(interaction: discord.Interaction, url: str = None, code: str = None):
    """Analyze JavaScript for sensitive information"""
    await process_analyze_js(interaction, url=url, code=code)

async def process_analyze_js(interaction: discord.Interaction, url: str = None, code: str = None):
    """Process JavaScript analysis logic"""
    if not url and not code:
        if interaction.response.is_done():
            await interaction.followup.send("❌ Please provide either a `url` or `code` to analyze.", ephemeral=True)
        else:
            await interaction.response.send_message("❌ Please provide either a `url` or `code` to analyze.", ephemeral=True)
        return
        
    if not interaction.response.is_done():
        await interaction.response.defer(thinking=True)
    
    try:
        import re
        js_content = ""
        source = "Provided Source"
        
        if url:
            source = url
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        js_content = await response.text()
                    else:
                        await interaction.followup.send(f"❌ Failed to fetch JS from URL (Status: {response.status})")
                        return
        else:
            js_content = code
            
        # Extract findings using ReconTools logic
        async with ReconTools() as recon:
            secrets = recon.find_secrets(js_content)
            endpoints = list(set(re.findall(r'["\'](/[a-zA-Z0-9_/.-]+)["\']', js_content)))
        
        # Format results
        embed = discord.Embed(
            title="🔍 JavaScript Analysis Results",
            description=f"Source: `{source[:100]}`",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        if secrets:
            # First 5 individual fields for visibility as requested "make it separate"
            for i, s in enumerate(secrets[:5]):
                embed.add_field(
                    name=f"🔐 Secret #{i+1}: {s['type']}",
                    value=f"`{s['value']}`\n{s.get('procedure', '')}"[:1024],
                    inline=False
                )
            
            # Remaining secrets in a summary if any
            if len(secrets) > 5:
                remaining_text = ""
                for s in secrets[5:15]:
                    remaining_text += f"• **{s['type']}**: `{s['value']}`\n"
                if len(secrets) > 15:
                    remaining_text += f"*... and {len(secrets)-15} more*"
                
                embed.add_field(
                    name=f"🔑 Additional Secrets ({len(secrets)-5})",
                    value=remaining_text[:1024],
                    inline=False
                )
        else:
            embed.add_field(name="🔑 Secrets Found", value="*None detected*", inline=False)
            
        if endpoints:
            # Clean and deduplicate endpoints
            unique_endpoints = sorted(list(set(endpoints)))
            endpoint_list = "\n".join([f"• `{e}`" for e in unique_endpoints[:15]])
            if len(unique_endpoints) > 15: endpoint_list += f"\n*... and {len(unique_endpoints)-15} more*"
            embed.add_field(name="🔗 Endpoints/Paths", value=f"```\n{endpoint_list}\n```", inline=False)
        else:
            embed.add_field(name="🔗 Endpoints/Paths", value="*None detected*", inline=False)
            
        # Extract variables
        var_patterns = [r'const\s+([a-zA-Z0-9_]+)\s*=', r'let\s+([a-zA-Z0-9_]+)\s*=', r'var\s+([a-zA-Z0-9_]+)\s*=']
        variables = []
        for p in var_patterns:
            variables.extend(re.findall(p, js_content))
        
        if variables:
            unique_vars = list(set(variables))[:20]
            var_list = ", ".join(unique_vars)
            if len(variables) > 20: var_list += " ..."
            embed.add_field(name="📝 Important Variables", value=f"```\n{var_list}\n```", inline=False)

        await interaction.followup.send(embed=embed)
        
    except Exception as e:
        await interaction.followup.send(f"❌ Error during JS analysis: `{str(e)}`")


@analyze_js.autocomplete('url')
async def analyze_js_autocomplete(interaction: discord.Interaction, current: str) -> List[app_commands.Choice[str]]:
    """Autocomplete for JS URLs discovered in scope"""
    js_files = scope_manager.get_js_files(interaction.guild.id)
    
    # Filter by current input
    choices = [
        app_commands.Choice(name=url if len(url) < 100 else f"...{url[-97:]}", value=url)
        for url in js_files if current.lower() in url.lower()
    ]
    
    return choices[:25] # Discord limit


@bot.event
async def on_ready():
    print(f'Logged in as {bot.user.name}')
    try:
        # Initialize wordlists
        created = check_and_create_wordlists()
        if created:
            print(f"Created default wordlists: {', '.join(created)}")
            
        # Initialize auto-scan manager
        await initialize_auto_scan_manager(bot, scope_manager)
        
        # Sync slash commands
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Startup error: {e}")

# ============================================
# RUN BOT
# ============================================

if __name__ == "__main__":
    from config import BOT_TOKEN
    bot.run(BOT_TOKEN)
