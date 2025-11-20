"""
Unified Report Generator for all APFA Agent modes.
Provides consistent reporting across llm-only, train, hybrid, and eval modes.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class ReportGenerator:
    """Unified report generator for all agent modes"""
    
    def __init__(self, output_dir: str = "data/agent_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_llm_only_report(
        self,
        config: Dict,
        results: List[Dict],
        nmap_results: Optional[Dict] = None
    ) -> Dict:
        """Generate report for LLM-only mode"""
        
        # Calculate stats
        total_ports_count = 0
        services_list = []
        if nmap_results:
            for host in nmap_results.get('hosts', []):
                for svc in host.get('services', []):
                    if svc.get('state') == 'open':
                        total_ports_count += 1
                        services_list.append(svc)
        
        report = {
            'metadata': {
                'mode': 'llm-only',
                'target_ip': config.get('target', {}).get('ip', 'unknown'),
                'scan_date': datetime.now().isoformat(),
                'agent_version': '1.0'
            },
            'scan_results': {
                'total_ports': total_ports_count,
                'services': services_list
            },
            'exploitation_results': {
                'total_attempts': len(results),
                'successful_exploits': sum(1 for r in results if r.get('success', False)),
                'failed_exploits': sum(1 for r in results if not r.get('success', False)),
                'success_rate': sum(1 for r in results if r.get('success', False)) / max(len(results), 1)
            },
            'attack_details': results
        }
        
        return self._save_report(report, 'llm_only')
    
    def generate_train_report(
        self,
        config: Dict,
        tool_manager: Any,
        training_timesteps: int,
        nmap_results: Optional[Dict] = None,
        agent: Any = None
    ) -> Dict:
        """Generate report for training mode"""
        
        # Get skill library stats
        skill_stats = {
            'total_skills': len(tool_manager.skills),
            'metasploit_modules': sum(1 for s in tool_manager.skills.values() if s.get('type') == 'metasploit'),
            'llm_generated': sum(1 for s in tool_manager.skills.values() if s.get('type') == 'llm_generated'),
            'success_rate_by_skill': {}
        }
        
        for sig, skill in tool_manager.skills.items():
            if skill.get('executions', 0) > 0:
                skill_stats['success_rate_by_skill'][sig] = {
                    'successes': skill.get('successes', 0),
                    'failures': skill.get('failures', 0),
                    'rate': skill.get('successes', 0) / skill.get('executions', 1)
                }
        
        report = {
            'metadata': {
                'mode': 'train',
                'target_ip': config.get('target', {}).get('ip', 'unknown'),
                'training_date': datetime.now().isoformat(),
                'agent_version': '1.0'
            },
            'training_config': {
                'total_timesteps': training_timesteps,
                'agent_info': str(getattr(agent, 'stats', {})),
                'learning_rate': config.get('learning_rate', 0.0003),
                'n_steps': config.get('n_steps', 2048),
                'batch_size': config.get('batch_size', 64)
            },
            'skill_library_stats': skill_stats,
            'scan_results': self._extract_scan_results(nmap_results)
        }
        
        return self._save_report(report, 'train')
    
    def generate_hybrid_report(
        self,
        config: Dict,
        nmap_results: Dict,
        state_manager: Any,
        tool_manager: Any,
        llm_client: Any,
        env: Any
    ) -> Dict:
        """Generate comprehensive report for hybrid mode"""
        
        stats = state_manager.get_statistics()
        
        # Enhanced Reporting for Successful Exploits
        successful_exploits_details = []
        compromised_ports = stats.get('compromised_ports', [])
        
        for port in compromised_ports:
            vuln = state_manager.port_to_vuln.get(port, {})
            
            # Try to find the successful skill
            port_index = state_manager.tracked_ports.index(port) if port in state_manager.tracked_ports else -1
            signature = state_manager.get_service_signature(port_index) if port_index >= 0 else None
            skill = tool_manager.skills.get(signature) if signature else None
            
            exploit_detail = {
                "port": port,
                "service": signature or "Unknown",
                "vulnerability_details": {
                    "name": vuln.get("pn", "Unknown"),
                    "cve": vuln.get("c", "N/A"),
                    "severity": vuln.get("s", "Unknown")
                },
                "access_level": "Root/System" if env.root_obtained else "User/Service",
                "replication_steps": "N/A"
            }
            
            if skill:
                if skill.get('type') == 'metasploit':
                    exploit_detail['replication_steps'] = (
                        f"Metasploit Module: {skill.get('module')}\n"
                        f"Options: RHOSTS=<target>, RPORT={port}"
                    )
                else:
                    code = skill.get('code', '')
                    exploit_detail['replication_steps'] = f"Execute Python Script:\n{code[:200]}..."
                    exploit_detail['full_code'] = code
            
            successful_exploits_details.append(exploit_detail)
        
        # Extract open ports
        open_ports_list = []
        if nmap_results and 'hosts' in nmap_results:
            for host in nmap_results['hosts']:
                for service in host.get('services', []):
                    if service.get('state') == 'open':
                        open_ports_list.append(service)
        
        report = {
            'metadata': {
                'mode': 'hybrid',
                'target_ip': config.get('target', {}).get('ip'),
                'scan_date': datetime.now().isoformat(),
                'agent_model': config.get('agent', {}).get('model_name'),
                'agent_version': '1.0'
            },
            'scan_results': {
                'total_ports': len(open_ports_list),
                'services': open_ports_list
            },
            'exploitation_results': {
                'total_attempts': stats.get('total_attempts', 0),
                'successful_exploits': stats.get('successful_exploits', 0),
                'failed_exploits': stats.get('total_attempts', 0) - stats.get('successful_exploits', 0),
                'success_rate': stats.get('success_rate', 0.0),
                'average_reward': stats.get('average_reward', 0.0),
                'root_obtained': env.root_obtained,
                'details': successful_exploits_details
            },
            'skill_library_stats': {
                'total_skills': len(tool_manager.skills),
                'skills_used': env.method_stats.get('cached_skill', 0),
                'method_distribution': env.method_stats
            },
            'compromised_services': compromised_ports,
            'attack_history': state_manager.action_history,
            'llm_stats': llm_client.stats if hasattr(llm_client, 'stats') else {}
        }
        
        return self._save_report(report, 'hybrid')
    
    def generate_eval_report(
        self,
        config: Dict,
        eval_results: Dict,
        n_episodes: int,
        tool_manager: Any
    ) -> Dict:
        """Generate report for evaluation mode"""
        
        report = {
            'metadata': {
                'mode': 'eval',
                'target_ip': config.get('target', {}).get('ip', 'unknown'),
                'evaluation_date': datetime.now().isoformat(),
                'agent_version': '1.0'
            },
            'evaluation_config': {
                'n_episodes': n_episodes
            },
            'evaluation_results': {
                'average_reward': eval_results.get('average_reward', 0.0),
                'success_rate': eval_results.get('success_rate', 0.0),
                'episodes_completed': eval_results.get('episodes', 0)
            },
            'skill_library_stats': {
                'total_skills': len(tool_manager.skills),
                'metasploit_modules': sum(1 for s in tool_manager.skills.values() if s.get('type') == 'metasploit'),
                'llm_generated': sum(1 for s in tool_manager.skills.values() if s.get('type') == 'llm_generated')
            }
        }
        
        return self._save_report(report, 'eval')
    
    def _extract_scan_results(self, nmap_results: Optional[Dict]) -> Dict:
        """Extract standardized scan results"""
        if not nmap_results:
            return {'total_ports': 0, 'services': []}
        
        open_ports = []
        for host in nmap_results.get('hosts', []):
            for service in host.get('services', []):
                if service.get('state') == 'open':
                    open_ports.append(service)
        
        return {
            'total_ports': len(open_ports),
            'services': open_ports
        }
    
    def _save_report(self, report: Dict, mode: str) -> Dict:
        """Save report to disk and return it"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.output_dir / f"{mode}_report_{timestamp}.json"
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Report saved to {report_path}")
        
        # Print summary
        if 'exploitation_results' in report:
            exp_results = report['exploitation_results']
            print(f"\nSummary:")
            print(f"  Total attempts: {exp_results.get('total_attempts', 0)}")
            print(f"  Successful: {exp_results.get('successful_exploits', 0)}")
            print(f"  Success rate: {exp_results.get('success_rate', 0.0):.1%}")
        
        if 'evaluation_results' in report:
            eval_results = report['evaluation_results']
            print(f"\nEvaluation Summary:")
            print(f"  Average Reward: {eval_results.get('average_reward', 0.0):.2f}")
            print(f"  Success Rate: {eval_results.get('success_rate', 0.0):.1%}")
        
        if 'skill_library_stats' in report:
            skill_stats = report['skill_library_stats']
            print(f"  Skills in library: {skill_stats.get('total_skills', 0)}")
        
        report['report_path'] = str(report_path)
        return report
