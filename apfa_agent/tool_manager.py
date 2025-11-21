import json
from pathlib import Path
from typing import Dict, Optional, Tuple
from datetime import datetime
import hashlib

class ToolManager:
    """
    Manages the Skill Library and Metasploit integration.
    
    This is the "memory" that allows the agent to learn from past successes
    and reuse proven exploits instead of regenerating them every time.
    """
    
    def __init__(
        self,
        skill_library_path: str = "data/agent_results/skill_library.json",
        msf_wrapper = None,
        rag_manager = None,
        max_failures: int = 3
    ):
        self.skill_library_path = Path(skill_library_path)
        self.msf_wrapper = msf_wrapper
        self.rag_manager = rag_manager
        self.max_failures = max_failures
        
        # Load existing skills
        self.skills = self._load_skills()
    
    def _load_skills(self) -> Dict:
        """Load skill library from disk"""
        if self.skill_library_path.exists():
            with open(self.skill_library_path) as f:
                data = json.load(f)
                return data.get('skills', {})
        return {}
    
    def save_skills(self):
        """Save skill library to disk"""
        self.skill_library_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'skills': self.skills,
            'metadata': {
                'total_skills': len(self.skills),
                'total_uses': sum(s['success_count'] + s['fail_count'] for s in self.skills.values()),
                'last_updated': datetime.now().isoformat()
            }
        }
        
        with open(self.skill_library_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_exploit_method(self, service_signature: str, port: Optional[int] = None) -> Tuple[str, Optional[Dict]]:
        """
        Decide which exploitation method to use with multi-tier fallback.
        
        Decision tree:
        1. Cached skill (fastest, +2.0 efficiency bonus) - validates port match
        2. Manual MSF mapping (reliable, +1.0 efficiency bonus)
        3. Auto-discovered MSF (learned, +1.0 efficiency bonus)
        4. Auto-discover new MSF (search database, +1.0 efficiency bonus if found)
        5. Search MSF database comprehensively (uses llm_tools.search_msf_modules)
        6. LLM generation (flexible, no bonus)
        
        Args:
            service_signature: Service signature (e.g., "vsftpd 2.3.4")
            port: Target port number (optional, used for cache validation)
        
        Returns:
            (method, data) where method is:
            - "cached_script": Use saved exploit code
            - "metasploit": Use MSF module (manual or auto-discovered)
            - "generate_new": Ask LLM to create new exploit
        """
        # 1. Check cached skills first (fastest)
        if service_signature in self.skills:
            skill = self.skills[service_signature]
            
            # Check decay rule
            if skill['fail_count'] >= self.max_failures:
                print(f"⚠️  Skill {service_signature} has {skill['fail_count']} failures, removing from cache")
                del self.skills[service_signature]
                self.save_skills()
            else:
                # Validate port match if port is specified
                cached_port = skill.get('port')
                if port is not None and cached_port is not None and port != cached_port:
                    print(f"⚠️  Cached skill port mismatch: cached={cached_port}, target={port}")
                    print(f"  Skipping cache and searching for new exploit")
                    # Don't use this cached entry - fall through to search
                else:
                    print(f"⚡ Using cached skill: {service_signature}")
                    # Return "cached_script" for any cached exploit code (regardless of original type)
                    # This ensures agent_mode.py can properly handle it
                    if skill.get('code'):
                        return ("cached_script", skill)
                    elif skill.get('module'):
                        return ("metasploit", skill)
                    else:
                        # Fallback to original type if neither code nor module
                        return (skill['type'], skill)
        
        # 2. Check Metasploit (manual → auto-discovered → auto-discover)
        if self.msf_wrapper:
            msf_module = self.msf_wrapper.get_module_info(service_signature)
            
            if msf_module:
                source = msf_module.get('source', 'unknown')
                if source == 'manual':
                    print(f"🔫 Using manual MSF module: {service_signature}")
                elif source == 'auto_discovered':
                    reliability = msf_module.get('reliability', 'unknown')
                    print(f"🔍 Using learned MSF module: {service_signature} (reliability: {reliability})")
                else:
                    print(f"🆕 Using newly discovered MSF module: {service_signature}")
                
                return ("metasploit", msf_module)
        
        # 3. Comprehensive MSF database search (NEW: prevents skipping to LLM prematurely)
        if self.msf_wrapper:
            print(f"🔍 Searching MSF database comprehensively for: {service_signature}")
            msf_search_result = self._search_msf_database(service_signature, port=port)
            
            if msf_search_result:
                print(f"🎯 Found MSF module via comprehensive search!")
                return ("metasploit", msf_search_result)
        
        # 4. Need to generate new exploit
        print(f"🤖 No cached/MSF exploit found, will generate new one for: {service_signature}")
        return ("generate_new", None)
    
    def _search_msf_database(self, service_signature: str, port: Optional[int] = None) -> Optional[Dict]:
        """
        Perform comprehensive MSF database search using llm_tools.
        
        This is called when manual mappings and auto-discovered modules don't match.
        It searches the entire MSF database and returns the best match if found.
        
        Args:
            service_signature: Service signature to search for
            port: Optional port number to help with search
            
        Returns:
            Module info dict if found, None otherwise
        """
        try:
            from apfa_agent.llm_tools import search_msf_modules
            
            # Parse service signature to extract components
            parts = service_signature.split()
            service = parts[0] if parts else service_signature
            version = parts[1] if len(parts) > 1 else None
            
            # Try to infer service from port if service is "unknown"
            if service.lower() == "unknown" and port:
                port_to_service = {
                    21: "ftp",
                    22: "ssh",
                    23: "telnet",
                    25: "smtp",
                    80: "http",
                    110: "pop3",
                    139: "smb",
                    143: "imap",
                    443: "https",
                    445: "smb",
                    3306: "mysql",
                    3389: "rdp",
                    5432: "postgresql",
                    6667: "irc",
                    8080: "http"
                }
                inferred_service = port_to_service.get(port)
                if inferred_service:
                    print(f"  ℹ️  Inferring service from port {port}: {inferred_service}")
                    service = inferred_service
                    service_signature = f"{service} {version}" if version else service
            
            # Search MSF database
            results = search_msf_modules(
                query=service_signature,
                service=service,
                version=version,
                port=port,
                msf_wrapper=self.msf_wrapper,
                max_results=5
            )
            
            if not results:
                return None
            
            # Get the best result (results are already sorted by reliability_score)
            best_match = results[0]
            
            # Check if reliability is acceptable
            reliability_score = best_match.get('reliability_score', 0)
            
            if reliability_score >= 2:  # At least "normal" rank
                print(f"    ✓ Best match: {best_match['module']} (score: {reliability_score})")
                
                # Return in the format expected by _execute_msf_module
                return {
                    'module': best_match['module'],
                    'source': 'comprehensive_search',
                    'reliability_score': reliability_score,
                    'rank': best_match.get('rank', 'unknown'),
                    'ports': best_match.get('ports', []),
                    'payload': best_match.get('payload', None),  # Let MSF wrapper auto-select
                    'description': best_match.get('description', ''),
                    'search_query': service_signature
                }
            else:
                print(f"    ⚠️  Best match has low reliability: {reliability_score} < 2")
                return None
                
        except ImportError:
            print(f"    ⚠️  llm_tools not available for MSF search")
            return None
        except Exception as e:
            print(f"    ⚠️  MSF database search failed: {e}")
            return None
    
    def add_skill(
        self,
        service_signature: str,
        skill_type: str,
        code: Optional[str] = None,
        module: Optional[str] = None,
        port: Optional[int] = None,
        success: bool = True
    ):
        """
        Add or update a skill in the library.
        
        Called after successful exploitation to "teach" the agent.
        """
        # Parameterize code before storing (make it reusable!)
        if code:
            code = self._param_code(code)
        
        if service_signature not in self.skills:
            # New skill
            self.skills[service_signature] = {
                'type': skill_type,
                'service_signature': service_signature,
                'port': port,
                'code': code,
                'module': module,
                'success_count': 0,
                'fail_count': 0,
                'last_used': None,
                'success_rate': 0.0
            }
        
        skill = self.skills[service_signature]
        
        # Update stats
        if success:
            skill['success_count'] += 1
            skill['fail_count'] = 0  # Reset failure streak
        else:
            skill['fail_count'] += 1
        
        skill['last_used'] = datetime.now().isoformat()
        total_uses = skill['success_count'] + skill['fail_count']
        skill['success_rate'] = skill['success_count'] / max(total_uses, 1)
        
        self.save_skills()
        
        print(f"📚 Updated skill library: {service_signature} "
              f"({skill['success_count']} successes, {skill['fail_count']} failures)")
    
    def get_cached_exploit(self, service_signature: str) -> Optional[str]:
        """Retrieve cached exploit code"""
        if service_signature in self.skills:
            return self.skills[service_signature].get('code')
        return None
    
    def clear_library(self):
        """Clear all skills (for agent reset scenarios)"""
        self.skills = {}
        self.save_skills()
        print("🔄 Skill library cleared")
    
    def _param_code(self, code: str) -> str:
        """
        Convert hardcoded IPs/ports to placeholders for reusability.
        Uses regex to find common IP patterns and port assignments.
        """
        import re
        
        # Find IP addresses in quotes and replace with environment variable
        # Pattern: "xxx.xxx.xxx.xxx" or 'xxx.xxx.xxx.xxx'
        ip_pattern = r'(["\'])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\1'
        
        # Replace hardcoded IPs with os.getenv call
        # target_ip = "192.168.1.1" -> target_ip = os.getenv("TARGET_IP", "192.168.1.1")
        code = re.sub(
            r'target_ip\s*=\s*(["\'])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\1',
            r'target_ip = os.getenv("TARGET_IP", \g<1>\g<2>\g<1>)',
            code
        )
        
        # Ensure os module is imported
        if 'import os' not in code:
            code = 'import os\n' + code
        
        print(f"📋 Parameterized exploit code for portability")
        return code
    
    def print_stats(self):
        """Print skill library statistics"""
        print("\n" + "="*60)
        print("SKILL LIBRARY STATISTICS")
        print("="*60)
        print(f"Total skills: {len(self.skills)}")
        
        for sig, skill in self.skills.items():
            print(f"\n{sig}:")
            print(f"  Type: {skill['type']}")
            print(f"  Success rate: {skill['success_rate']:.1%}")
            print(f"  Uses: {skill['success_count'] + skill['fail_count']}")
            print(f"  Last used: {skill['last_used']}")
