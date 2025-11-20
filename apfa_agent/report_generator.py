"""
Unified Report Generator for APFA Agent.
Provides consistent reporting for LLM-based pentesting mode.
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
    
    def generate_agent_report(
        self,
        config: Dict,
        results: List[Dict],
        nmap_results: Optional[Dict] = None
    ) -> Dict:
        """Generate report for Agent mode"""
        
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
                'mode': 'agent',
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
        
        return self._save_report(report, 'agent')
    

    

    

    
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
            print(f"  Success Rate: {eval_results.get('success_rate', 0.0):.1%}")
        
        if 'skill_library_stats' in report:
            skill_stats = report['skill_library_stats']
            print(f"  Skills in library: {skill_stats.get('total_skills', 0)}")
        
        report['report_path'] = str(report_path)
        return report
