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
    
    def get_exploit_method(self, service_signature: str) -> Tuple[str, Optional[Dict]]:
        """
        Decide which exploitation method to use with multi-tier fallback.
        
        Decision tree:
        1. Cached skill (fastest, +2.0 efficiency bonus)
        2. Manual MSF mapping (reliable, +1.0 efficiency bonus)
        3. Auto-discovered MSF (learned, +1.0 efficiency bonus)
        4. Auto-discover new MSF (search database, +1.0 efficiency bonus if found)
        5. LLM generation (flexible, no bonus)
        
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
                print(f"⚡ Using cached skill: {service_signature}")
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
        
        # 3. Need to generate new exploit
        print(f"🤖 No cached/MSF exploit found, will generate new one for: {service_signature}")
        return ("generate_new", None)
    
    def add_skill(
        self,
        service_signature: str,
        skill_type: str,
        code: str = None,
        module: str = None,
        port: int = None,
        success: bool = True
    ):
        """
        Add or update a skill in the library.
        
        Called after successful exploitation to "teach" the agent.
        """
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
        """Clear all skills (for training mode with reset_always)"""
        self.skills = {}
        self.save_skills()
        print("🔄 Skill library cleared")
    
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
