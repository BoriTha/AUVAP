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
from apfa_agent.prompts import SYSTEM_PROMPT, RAG_CONTEXT_PROMPT, ERROR_RETRY_PROMPT
from apfa_agent.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

class SmartTriageAgent:
    """
    LLM-only mode (Smart Triage).
    Executes attacks sequentially based on LLM ranking, without RL.
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
        self.tool_manager = ToolManager()
        self.rag_manager = RAGManager() # Assuming it exists
        self.report_generator = ReportGenerator("data/agent_results")

    def run(self, classified_json_path: Optional[str] = None, nmap_results: Optional[Dict] = None):
        """
        Run the Smart Triage process.
        """
        print("🚀 Starting Smart Triage (LLM-only mode)...")
        
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
            
            # 2. Check if we have a cached skill or MSF module
            # In LLM-only mode, we might still want to use known tools if available
            # But the prompt emphasizes "Execute attacks sequentially (no RL)" and "Use RAG".
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
        report = self.report_generator.generate_llm_only_report(
            config=self.config,
            results=results,
            nmap_results=nmap_results
        )
        print("\n🏁 Smart Triage completed.")
        return results

    def _attack_target(self, target: Dict) -> tuple[bool, Dict]:
        """
        Attack a single target using LLM generation + RAG.
        """
        service_sig = f"{target['service']} {target.get('version', '')}".strip()
        target_ip = target['ip']
        port = int(target['port'])
        vuln_name = target.get('original', {}).get('name', 'Unknown')
        
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
        
        # 5. Retry (keep tool calling enabled for retry)
        if not result['success'] and result['status'] != 'security_violation':
            print("  ⚠️  Retrying...")
            retry_prompt = ERROR_RETRY_PROMPT.format(error=result.get('output', 'Unknown error'))
            code = self.llm_client.generate_code(retry_prompt, target_info=target_info, use_tools=False)  # Don't re-query tools on retry
            result = self.executor.execute(code, target_ip, port)
            
        return result['success'], result

    def _generate_report(self, results: List[Dict]):
        """
        DEPRECATED: Use report_generator.generate_llm_only_report() instead.
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
