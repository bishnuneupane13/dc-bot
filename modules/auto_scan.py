"""
Automated Scanning Module
========================
Background tasks for continuous domain monitoring and automated scanning.
"""

import asyncio
import discord
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
import json
import os


@dataclass
class ScanTask:
    """Represents a scheduled scan task"""
    id: str
    domain: str
    guild_id: int
    channel_id: int
    scan_type: str  # 'full', 'subdomain', 'live', 'tech', 'vuln'
    interval_minutes: int
    next_run: datetime
    created_at: datetime
    enabled: bool = True
    last_run: Optional[datetime] = None
    last_results: Dict[str, Any] = field(default_factory=dict)


class AutoScanManager:
    """
    Manages automated scanning and background monitoring tasks.
    """
    
    def __init__(self, bot, scope_manager, data_file: str = "autoscans.json"):
        self.bot = bot
        self.scope_manager = scope_manager
        self.data_file = data_file
        self.scan_tasks: Dict[str, ScanTask] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.load_data()
    
    def load_data(self):
        """Load scheduled scan tasks from file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    for task_id, task_data in data.get('tasks', {}).items():
                        task = ScanTask(
                            id=task_data['id'],
                            domain=task_data['domain'],
                            guild_id=task_data['guild_id'],
                            channel_id=task_data['channel_id'],
                            scan_type=task_data['scan_type'],
                            interval_minutes=task_data['interval_minutes'],
                            next_run=datetime.fromisoformat(task_data['next_run']),
                            created_at=datetime.fromisoformat(task_data['created_at']),
                            enabled=task_data.get('enabled', True),
                            last_run=datetime.fromisoformat(task_data['last_run']) if task_data.get('last_run') else None,
                            last_results=task_data.get('last_results', {})
                        )
                        self.scan_tasks[task_id] = task
            except Exception as e:
                print(f"Error loading auto-scan data: {e}")
    
    def save_data(self):
        """Save scheduled scan tasks to file"""
        try:
            data = {
                'tasks': {
                    task_id: {
                        'id': task.id,
                        'domain': task.domain,
                        'guild_id': task.guild_id,
                        'channel_id': task.channel_id,
                        'scan_type': task.scan_type,
                        'interval_minutes': task.interval_minutes,
                        'next_run': task.next_run.isoformat(),
                        'created_at': task.created_at.isoformat(),
                        'enabled': task.enabled,
                        'last_run': task.last_run.isoformat() if task.last_run else None,
                        'last_results': task.last_results
                    }
                    for task_id, task in self.scan_tasks.items()
                }
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving auto-scan data: {e}")
    
    async def create_scan_task(self, domain: str, guild_id: int, channel_id: int, 
                              scan_type: str, interval_minutes: int) -> str:
        """Create a new scheduled scan task"""
        # Normalize domain
        if self.scope_manager:
             domain = self.scope_manager.normalize_domain(domain)
        else:
             # Fallback if scope_manager not yet loaded (shouldn't happen often)
             domain = domain.lower().replace('https://', '').replace('http://', '').split('/')[0]

        task_id = f"scan_{guild_id}_{domain}_{datetime.now().timestamp()}"
        
        task = ScanTask(
            id=task_id,
            domain=domain,
            guild_id=guild_id,
            channel_id=channel_id,
            scan_type=scan_type,
            interval_minutes=interval_minutes,
            next_run=datetime.now() + timedelta(minutes=interval_minutes),
            created_at=datetime.now()
        )
        
        self.scan_tasks[task_id] = task
        self.save_data()
        
        # Start the background task
        await self.start_task(task_id)
        
        return task_id
    
    async def start_task(self, task_id: str):
        """Start a background scanning task"""
        if task_id in self.running_tasks:
            self.running_tasks[task_id].cancel()
        
        task = self.scan_tasks[task_id]
        background_task = asyncio.create_task(self.background_scan_loop(task))
        self.running_tasks[task_id] = background_task
    
    async def stop_task(self, task_id: str):
        """Stop a background scanning task"""
        if task_id in self.running_tasks:
            self.running_tasks[task_id].cancel()
            del self.running_tasks[task_id]
    
    async def background_scan_loop(self, task: ScanTask):
        """Background loop that runs scheduled scans"""
        while task.enabled and task.id in self.scan_tasks:
            now = datetime.now()
            if now >= task.next_run:
                try:
                    await self.execute_scan(task)
                    task.last_run = now
                    task.next_run = now + timedelta(minutes=task.interval_minutes)
                    self.save_data()
                except Exception as e:
                    print(f"Error in background scan: {e}")
            
            # Wait a bit before checking again
            await asyncio.sleep(30)
    
    async def execute_scan(self, task: ScanTask):
        """Execute a scheduled scan"""
        from modules.recon import ReconTools
        from modules.httpx_tools import HttpxTools
        from modules.advanced_tools import AdvancedTools
        from modules.scanner import VulnScanner
        
        guild = self.bot.get_guild(int(task.guild_id))
        if not guild:
            return
        
        channel = guild.get_channel(task.channel_id)
        if not channel:
            return
        
        async with ReconTools() as recon, HttpxTools() as httpx, AdvancedTools() as advanced, VulnScanner() as scanner:
            try:
                embed = discord.Embed(
                    title=f"🔄 Auto-Scan: {task.domain}",
                    description=f"Running {task.scan_type} scan...",
                    color=discord.Color.blue(),
                    timestamp=datetime.now()
                )
                await channel.send(embed=embed)
                
                results = {}
                
                if task.scan_type == "full":
                    # Run comprehensive scan
                    subdomains = await recon.subdomain_enum(task.domain)
                    results['subdomains'] = subdomains
                    
                    if subdomains:
                        live_domains = await httpx.probe_domains(subdomains[:50])
                        results['live_domains'] = live_domains
                        
                        await self.scope_manager.post_subdomains(guild, task.domain, subdomains, f"Auto-scan ({task.id})")
                        await self.scope_manager.post_live_domains(guild, task.domain, live_domains, f"Auto-scan ({task.id})")
                    
                    tech = await httpx.detect_technology(task.domain)
                    results['technology'] = tech
                    await self.scope_manager.post_technology(guild, task.domain, tech, f"Auto-scan ({task.id})")
                    
                    ports = await recon.port_scan(task.domain)
                    results['ports'] = ports
                    await self.scope_manager.post_ports(guild, task.domain, ports, f"Auto-scan ({task.id})")
                    
                    params = await recon.find_parameters(task.domain)
                    results['parameters'] = params
                    await self.scope_manager.post_parameters(guild, task.domain, params, f"Auto-scan ({task.id})")
                    
                    js_files = await recon.find_js_files(task.domain)
                    results['js_files'] = js_files
                    await self.scope_manager.post_js_files(guild, task.domain, js_files, f"Auto-scan ({task.id})")
                    
                    endpoints = await recon.extract_endpoints(task.domain)
                    results['endpoints'] = endpoints
                    await self.scope_manager.post_endpoints(guild, task.domain, endpoints, f"Auto-scan ({task.id})")
                    
                    # 10. Smart AI Analysis
                    from modules.vuln_analysis import SmartAnalyzer
                    analyzer = SmartAnalyzer()
                    
                    # Analyze Tech Stack
                    tech_findings = analyzer.analyze_tech_stack(tech.get('technologies', []))
                    for finding in tech_findings:
                        await self.scope_manager.post_finding(
                            guild, task.domain, finding['title'], finding['description'],
                            finding['severity'], f"Auto-Scan ({task.id})",
                            procedure=finding.get('procedure')
                        )
                    
                    # Analyze URLs (Endpoints + JS + Parameters)
                    all_urls = (results.get('endpoints', []) or []) + (results.get('js_files', []) or []) + (results.get('parameters', []) or [])
                    url_findings = analyzer.analyze_urls(all_urls[:200])
                    for finding in url_findings:
                        await self.scope_manager.post_finding(
                            guild, task.domain, finding['title'], finding['description'],
                            finding['severity'], f"Auto-Scan ({task.id})",
                            procedure=finding.get('procedure')
                        )
                    
                    # Smart JS File Analysis
                    js_findings = analyzer.analyze_js_files_smart(results.get('js_files', []) or [])
                    for finding in js_findings:
                        await self.scope_manager.post_finding(
                            guild, task.domain, finding['title'], finding['description'],
                            finding['severity'], f"Auto-Scan ({task.id})",
                            procedure=finding.get('procedure')
                        )
                        
                    # Generate and post AI Report
                    scan_data = {
                        'technologies': tech.get('technologies', []),
                        'vulns': tech_findings + url_findings + js_findings
                    }
                    ai_report = analyzer.generate_ai_report(task.domain, scan_data)
                    await self.scope_manager.post_finding(
                        guild, task.domain, "🤖 AI Strategic Assessment", ai_report, "Info", f"Auto-Scan ({task.id})"
                    )
                
                elif task.scan_type == "subdomain":
                    subdomains = await recon.subdomain_enum(task.domain)
                    results['subdomains'] = subdomains
                    await self.scope_manager.post_subdomains(guild, task.domain, subdomains, f"Auto-scan ({task.id})")
                
                elif task.scan_type == "live":
                    # Check main domain and common subdomains
                    domains_to_check = [
                        f"https://{task.domain}", f"http://{task.domain}",
                        f"https://www.{task.domain}", f"http://www.{task.domain}",
                        f"https://mail.{task.domain}", f"http://mail.{task.domain}"
                    ]
                    live_domains = await httpx.probe_domains(domains_to_check)
                    results['live_domains'] = live_domains
                    await self.scope_manager.post_live_domains(guild, task.domain, live_domains, f"Auto-scan ({task.id})")
                
                elif task.scan_type == "tech":
                    tech = await httpx.detect_technology(task.domain)
                    results['technology'] = tech
                    await self.scope_manager.post_technology(guild, task.domain, tech, f"Auto-scan ({task.id})")
            
                elif task.scan_type == "vuln":
                    # Passive vulnerability analysis
                    vulns = []
                    
                    # Check for security headers and basic tech exposure
                    target_url = f"https://{task.domain}"
                    analysis = await scanner.analyze_url(target_url)
                    
                    if analysis.get('potential_issues'):
                        vulns.extend(analysis['potential_issues'])
                    
                    # WAF check is also passive
                    waf_check = await advanced.detect_waf(task.domain)
                    if waf_check.get('waf_detected'):
                        vulns.append({
                            'type': 'WAF Detected',
                            'info': waf_check.get('waf_name'),
                            'severity': 'Info'
                        })
                    
                    results['passive_analysis'] = analysis
                    results['vulnerabilities'] = vulns
                
                # Update task results
                task.last_results = results
                self.save_data()
                
                # Send completion message
                embed = discord.Embed(
                    title=f"✅ Auto-Scan Complete: {task.domain}",
                    description=f"{task.scan_type.title()} scan finished",
                    color=discord.Color.green(),
                    timestamp=datetime.now()
                )
                embed.add_field(name="Next Run", value=f"<t:{int((task.next_run.timestamp()))}:R>", inline=True)
                await channel.send(embed=embed)
                
            except Exception as e:
                embed = discord.Embed(
                    title=f"❌ Auto-Scan Error: {task.domain}",
                    description=f"Error during {task.scan_type} scan: {str(e)}",
                    color=discord.Color.red(),
                    timestamp=datetime.now()
                )
                await channel.send(embed=embed)
    
    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a scheduled task"""
        if task_id not in self.scan_tasks:
            return None
        
        task = self.scan_tasks[task_id]
        return {
            'id': task.id,
            'domain': task.domain,
            'scan_type': task.scan_type,
            'interval_minutes': task.interval_minutes,
            'enabled': task.enabled,
            'next_run': task.next_run,
            'last_run': task.last_run,
            'running': task_id in self.running_tasks
        }
    
    async def list_tasks_for_guild(self, guild_id: int) -> List[ScanTask]:
        """List all scan tasks for a guild"""
        return [task for task in self.scan_tasks.values() if task.guild_id == guild_id]
    
    async def enable_task(self, task_id: str):
        """Enable a scheduled task"""
        if task_id in self.scan_tasks:
            self.scan_tasks[task_id].enabled = True
            await self.start_task(task_id)
            self.save_data()
    
    async def disable_task(self, task_id: str):
        """Disable a scheduled task"""
        if task_id in self.scan_tasks:
            self.scan_tasks[task_id].enabled = False
            await self.stop_task(task_id)
            self.save_data()
    
    async def remove_task(self, task_id: str):
        """Remove a scheduled task"""
        if task_id in self.scan_tasks:
            await self.stop_task(task_id)
            del self.scan_tasks[task_id]
            self.save_data()


    async def start_startup_tasks(self):
        """Start all enabled tasks loaded from storage"""
        print(f"🔄 Restarting {len(self.scan_tasks)} auto-scan tasks...")
        count = 0
        for task_id, task in self.scan_tasks.items():
            if task.enabled:
                await self.start_task(task_id)
                count += 1
        print(f"✅ Restarted {count} auto-scan tasks")


# Global auto-scan manager instance
auto_scan_manager = AutoScanManager(bot=None, scope_manager=None)  # Will be initialized later


async def initialize_auto_scan_manager(bot, scope_mgr):
    """Initialize the auto-scan manager with scope manager"""
    global auto_scan_manager
    
    # Always update references
    auto_scan_manager.bot = bot
    auto_scan_manager.scope_manager = scope_mgr
    
    # Ensure scope_mgr has the attribute (Duck typing)
    if hasattr(scope_mgr, 'auto_scan_manager'):
        scope_mgr.auto_scan_manager = auto_scan_manager
    
    # Start the startup tasks properly
    await auto_scan_manager.start_startup_tasks()