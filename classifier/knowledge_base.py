#!/usr/bin/env python3
"""
Knowledge Base Manager for Vulnerability Classification
Loads and manages CWE, MITRE ATT&CK, and pattern-based knowledge
"""

import json
import os
from typing import Dict, List, Optional, Any
from pathlib import Path


class KnowledgeBase:
    """Manages classification knowledge including patterns, CWE, and MITRE ATT&CK"""
    
    def __init__(self, classifier_dir: Optional[str] = None):
        """
        Initialize knowledge base
        
        Args:
            classifier_dir: Path to Classifier directory (auto-detected if None)
        """
        if classifier_dir is None:
            # Auto-detect based on this file's location
            self.classifier_dir = Path(__file__).parent
        else:
            self.classifier_dir = Path(classifier_dir)
        self.data_dir = self.classifier_dir / "data"
        
        # Knowledge stores
        self.patterns: Dict[str, Any] = {}
        self.cve_mappings: Dict[str, Any] = {}
        self.port_mappings: Dict[str, Any] = {}
        
        # Load all knowledge
        self._load_patterns()
    
    def _load_patterns(self):
        """Load pattern-based classification rules"""
        patterns_file = self.classifier_dir / "patterns.json"
        
        if not patterns_file.exists():
            raise FileNotFoundError(f"Patterns file not found: {patterns_file}")
        
        with open(patterns_file, 'r') as f:
            data = json.load(f)
        
        self.patterns = data.get("patterns", {})
        self.port_mappings = data.get("port_mappings", {})
        self.cve_mappings = data.get("cve_patterns", {})
    
    def match_pattern(self, text: str, plugin_name: str = "") -> List[Dict[str, Any]]:
        """
        Match text against known vulnerability patterns
        
        Args:
            text: Text to match (description, plugin name, etc.)
            plugin_name: Optional plugin name for additional context
        
        Returns:
            List of matching patterns with confidence scores
        """
        text_lower = text.lower()
        plugin_lower = plugin_name.lower()
        combined_text = f"{text_lower} {plugin_lower}"
        
        matches = []
        
        for pattern_name, pattern_data in self.patterns.items():
            keywords = pattern_data.get("keywords", [])
            
            # Calculate match score
            matched_keywords = []
            for keyword in keywords:
                if keyword.lower() in combined_text:
                    matched_keywords.append(keyword)
            
            if matched_keywords:
                # Confidence based on keyword match ratio and strength
                confidence = min(1.0, len(matched_keywords) / len(keywords) + 0.3)
                
                matches.append({
                    "pattern_name": pattern_name,
                    "pattern_data": pattern_data,
                    "matched_keywords": matched_keywords,
                    "confidence": confidence
                })
        
        # Sort by confidence (highest first)
        matches.sort(key=lambda x: x["confidence"], reverse=True)
        
        return matches
    
    def lookup_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Lookup classification data for a specific CVE
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2020-1745")
        
        Returns:
            CVE classification data or None if not found
        """
        return self.cve_mappings.get(cve_id)
    
    def get_port_context(self, port: int) -> Optional[Dict[str, Any]]:
        """
        Get service and attack context for a port
        
        Args:
            port: Port number
        
        Returns:
            Port context data or None if not found
        """
        return self.port_mappings.get(str(port))
    
    def get_pattern(self, pattern_name: str) -> Optional[Dict[str, Any]]:
        """Get a specific pattern by name"""
        return self.patterns.get(pattern_name)
    
    def all_patterns(self) -> Dict[str, Any]:
        """Get all patterns"""
        return self.patterns
    
    def search_similar_cwe(self, description: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar CWE entries based on description
        
        NOTE: This is a placeholder for RAG-based similarity search.
        In full implementation, this would use vector embeddings.
        
        Args:
            description: Vulnerability description
            top_k: Number of results to return
        
        Returns:
            List of similar CWE entries
        """
        # For now, return empty list
        # In full RAG implementation, this would:
        # 1. Embed the description
        # 2. Search vector store for similar CWE descriptions
        # 3. Return top_k matches
        return []
    
    def search_similar_attack(self, description: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar MITRE ATT&CK techniques
        
        NOTE: Placeholder for RAG-based similarity search.
        
        Args:
            description: Vulnerability description
            top_k: Number of results to return
        
        Returns:
            List of similar ATT&CK techniques
        """
        return []


# Singleton instance
_knowledge_base: Optional[KnowledgeBase] = None


def get_knowledge_base() -> KnowledgeBase:
    """Get or create singleton knowledge base instance"""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
    return _knowledge_base


if __name__ == "__main__":
    # Test the knowledge base
    kb = KnowledgeBase()
    
    print("Loaded patterns:", len(kb.patterns))
    print("Loaded port mappings:", len(kb.port_mappings))
    print("Loaded CVE mappings:", len(kb.cve_mappings))
    
    # Test pattern matching
    test_desc = "The remote server has a backdoor that allows remote code execution"
    matches = kb.match_pattern(test_desc)
    print(f"\nPattern matches for test description:")
    for match in matches:
        print(f"  - {match['pattern_name']}: {match['confidence']:.2f}")
    
    # Test CVE lookup
    cve_data = kb.lookup_cve("CVE-2020-1745")
    if cve_data:
        print(f"\nCVE-2020-1745 data: {cve_data['name']}")
    
    # Test port context
    port_ctx = kb.get_port_context(22)
    if port_ctx:
        print(f"\nPort 22 context: {port_ctx['service']}")
