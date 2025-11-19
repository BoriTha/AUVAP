import json
from typing import List, Dict

class LLMRanker:
    """
    Ranks vulnerabilities for LLM-only mode.
    Prioritizes easy/well-known exploits first.
    """
    
    EASY_EXPLOITS = {
        'vsftpd 2.3.4': 10,
        'unrealircd': 9,
        'samba 3.0.20': 9,
        'distcc': 8,
        'postgresql': 7
    }
    
    def __init__(self, ranking_strategy: str = "easy_first"):
        self.strategy = ranking_strategy
    
    def rank_targets(self, classified_json_path: str) -> List[Dict]:
        """
        Load APFA classified vulnerabilities and rank them.
        
        Returns:
            Sorted list of targets to attack
        """
        with open(classified_json_path) as f:
            data = json.load(f)
        
        vulns = data.get('vulnerabilities', [])
        return self.rank_list(vulns)

    def rank_list(self, vulns: List[Dict]) -> List[Dict]:
        """Rank a list of vulnerability dictionaries"""
        if self.strategy == "easy_first":
            return self._rank_by_ease(vulns)
        elif self.strategy == "critical_first":
            return self._rank_by_cvss(vulns)
        else:
            return vulns  # No ranking
    
    def _rank_by_ease(self, vulns: List[Dict]) -> List[Dict]:
        """Prioritize well-known, easy exploits"""
        def score(vuln):
            service = vuln['original']['pn'].lower()
            
            # Check if it's a known easy exploit
            for easy_name, easy_score in self.EASY_EXPLOITS.items():
                if easy_name in service:
                    return easy_score
            
            # Fallback to CVSS
            return vuln['original'].get('cvss', 0) / 10.0
        
        return sorted(vulns, key=score, reverse=True)
    
    def _rank_by_cvss(self, vulns: List[Dict]) -> List[Dict]:
        """Prioritize by CVSS score (critical first)"""
        return sorted(vulns, key=lambda v: v['original'].get('cvss', 0), reverse=True)
