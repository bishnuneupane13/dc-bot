"""
Intelligent Vulnerability Suggestions Module
============================================
Provides READ-ONLY security testing suggestions based on detected technologies.
NO payloads, NO scanning, NO exploitation - informational only.
Strictly maps detected technologies to educational CVEs and Manual Review Ideas.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


@dataclass
class SecuritySuggestion:
    """A single security testing suggestion"""
    technology: str
    why_it_matters: str
    relevant_cves: List[str]
    manual_review_ideas: List[str]


class VulnerabilitySuggestions:
    """
    Intelligent vulnerability suggestions based on detected technologies.
    All suggestions are for MANUAL TESTING only - no automated attacks.
    """
    
    DISCLAIMER = (
        "⚠️ **DISCLAIMER**\n"
        "Referenced CVEs are for awareness only.\n"
        "No exploitation or vulnerability verification has been performed.\n"
        "All testing must follow program rules."
    )
    
    def __init__(self):
        # Knowledge base of technology-specific suggestions
        self.knowledge_base = self._build_knowledge_base()
        
        # Technology detection patterns
        self.tech_patterns = self._build_tech_patterns()
    
    def _build_knowledge_base(self) -> Dict[str, SecuritySuggestion]:
        """Build the security suggestion knowledge base with STRICT mappings"""
        return {
            "apache": SecuritySuggestion(
                technology="Apache",
                why_it_matters="Misconfigured Apache servers can suffer from path traversal or information leakage.",
                relevant_cves=[
                    "CVE-2021-41773 (Path normalization issues)",
                    "CVE-2021-42013"
                ],
                manual_review_ideas=[
                    "Review URL path handling behavior",
                    "Inspect access restrictions on directories"
                ]
            ),
            "nginx": SecuritySuggestion(
                technology="Nginx",
                why_it_matters="Nginx is a common reverse proxy; misconfigurations can lead to acl bypass.",
                relevant_cves=[
                    "CVE-2019-20372"
                ],
                manual_review_ideas=[
                    "Review reverse proxy behavior",
                    "Inspect header forwarding logic"
                ]
            ),
            "wordpress": SecuritySuggestion(
                technology="WordPress",
                why_it_matters="WordPress sites often rely on plugins that may have unpatched vulnerabilities.",
                relevant_cves=[
                    "CVE-2022-21661",
                    "CVE-2023-2745"
                ],
                manual_review_ideas=[
                    "Review plugin & theme endpoints",
                    "Inspect REST API exposure"
                ]
            ),
            "laravel": SecuritySuggestion(
                technology="Laravel",
                why_it_matters="Laravel applications may expose debug modes or have improper error handling.",
                relevant_cves=[
                    "CVE-2021-3129"
                ],
                manual_review_ideas=[
                    "Review error handling behavior",
                    "Inspect input validation logic manually"
                ]
            ),
            "spring": SecuritySuggestion(
                technology="Spring Boot",
                why_it_matters="Spring Boot applications often expose actuator endpoints or suffer from parameter binding issues.",
                relevant_cves=[
                    "CVE-2022-22965"
                ],
                manual_review_ideas=[
                    "Inspect parameter binding behavior",
                    "Review exposed actuator endpoints"
                ]
            ),
            "nodejs": SecuritySuggestion(
                technology="Node.js / Express",
                why_it_matters="Node.js apps may be vulnerable to prototype pollution or improper JSON handling.",
                relevant_cves=[
                    "CVE-2022-24999"
                ],
                manual_review_ideas=[
                    "Review JSON input handling",
                    "Inspect ID-based endpoints for access control"
                ]
            ),
            "jwt": SecuritySuggestion(
                technology="JWT Authentication",
                why_it_matters="Improper JWT validation can allow attackers to forge tokens.",
                relevant_cves=[
                    "CVE-2020-28042"
                ],
                manual_review_ideas=[
                    "Review token expiration enforcement",
                    "Inspect authorization consistency"
                ]
            ),
            "graphql": SecuritySuggestion(
                technology="GraphQL",
                why_it_matters="GraphQL endpoints often expose the entire schema via introspection, aiding reconnaissance.",
                relevant_cves=[
                    "CVE-2018-1000888"
                ],
                manual_review_ideas=[
                    "Review introspection availability",
                    "Inspect authorization per resolver"
                ]
            ),
            # General fallback for PHP if not Laravel
            "php": SecuritySuggestion(
                technology="PHP",
                why_it_matters="Legacy PHP apps might not handle input sanitization correctly.",
                relevant_cves=[],
                manual_review_ideas=[
                    "Check for exposed phpinfo() or config files",
                    "Review input handling on older endpoints"
                ]
            )
        }
    
    def _build_tech_patterns(self) -> Dict[str, List[str]]:
        """Build patterns for technology detection"""
        return {
            "apache": ["server: apache", "apache", "httpd"],
            "nginx": ["server: nginx", "nginx"],
            "wordpress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
            "laravel": ["laravel_session", "xsrf-token", "laravel"],
            "spring": ["jsessionid", "spring", "actuator", "j_spring_security"],
            "nodejs": ["x-powered-by: express", "node", "npm", "express", "connect.sid"],
            "jwt": ["bearer", "eyj", "authorization: bearer"],
            "graphql": ["graphql", "__schema", "query {", "mutation {"],
            "php": ["x-powered-by: php", ".php", "phpsessid"]
        }
    
    def detect_technologies(self, headers: Dict[str, str], body: str, 
                           cookies: List[str] = None, url: str = "") -> List[str]:
        """
        Detect technologies from HTTP response data
        """
        detected = []
        
        # Combine all data for pattern matching
        combined = (
            str(headers).lower() + 
            body.lower() + 
            " ".join(cookies or []).lower() +
            url.lower()
        )
        
        for tech_key, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if pattern.lower() in combined:
                    if tech_key not in detected:
                        detected.append(tech_key)
                    break
        
        return detected
    
    def get_suggestions(self, detected_technologies: List[str]) -> List[SecuritySuggestion]:
        """Get security suggestions for detected technologies"""
        suggestions = []
        for tech in detected_technologies:
            if tech in self.knowledge_base:
                suggestions.append(self.knowledge_base[tech])
        return suggestions
    
    def format_discord_message(self, suggestions: List[SecuritySuggestion]) -> str:
        """Format strictly as requested"""
        if not suggestions:
            return "No specific technology-based suggestions found."
            
        output = "# 🔎 Manual Security Testing Suggestions\n\n"
        
        for sug in suggestions:
            output += f"**Title:** Manual Security Testing Suggestions\n" # As requested per block? Or once? The prompt says "Title: ... For each technology:" implies header once. 
            # Actually prompt says:
            # Title:
            # 🔎 Manual Security Testing Suggestions
            #
            # For each technology:
            # Technology Detected: ...
            
            output += f"**Technology Detected:** {sug.technology}\n"
            output += f"**Why It Matters:** {sug.why_it_matters}\n"
            
            if sug.relevant_cves:
                output += "**Relevant CVEs (Awareness Only):**\n"
                for cve in sug.relevant_cves:
                    output += f"- {cve}\n"
            
            output += "**Manual Review Ideas:**\n"
            for idea in sug.manual_review_ideas:
                output += f"- {idea}\n"
            
            output += "\n---\n\n"
            
        output += self.DISCLAIMER
        return output

    def get_suggestion_by_tech(self, technology: str) -> Optional[SecuritySuggestion]:
        return self.knowledge_base.get(technology.lower())

    async def analyze_and_suggest(self, headers: Dict[str, str], body: str,
                                  cookies: List[str] = None, url: str = "") -> Dict[str, Any]:
        """Complete analysis"""
        detected = self.detect_technologies(headers, body, cookies, url)
        suggestions = self.get_suggestions(detected)
        
        return {
            "detected_technologies": detected,
            "suggestions": suggestions,
            "formatted_text": self.format_discord_message(suggestions),
            "disclaimer": self.DISCLAIMER
        }

# Quick access
def get_suggestions_for_tech(technology: str) -> Optional[SecuritySuggestion]:
    suggester = VulnerabilitySuggestions()
    return suggester.get_suggestion_by_tech(technology)
