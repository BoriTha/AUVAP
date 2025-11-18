#!/usr/bin/env python3
"""
Example: Classify vulnerabilities using the Vulnerability Classifier

This script demonstrates:
1. Loading vulnerability data from parser output
2. Classifying vulnerabilities with pattern matching
3. Saving enriched output for RL agent consumption
4. Different classification modes
"""

import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from classifier.vulnerability_classifier import VulnerabilityClassifier, classify_from_file  # type: ignore


def example_basic_classification():
    """Example 1: Basic classification with pattern matching"""
    print("="*60)
    print("Example 1: Basic Pattern-Based Classification")
    print("="*60)
    
    # Load sample data
    input_file = "data/output/critical_ms2_scan.json"
    
    # Classify using pattern matching only (fast, no API calls)
    classifier = VulnerabilityClassifier(mode="pattern", enable_rag=False)
    
    with open(input_file, 'r') as f:
        vulnerabilities = json.load(f)
    
    # Classify first 3 vulnerabilities as examples
    print(f"\nClassifying first 3 vulnerabilities from {input_file}...\n")
    
    for i, vuln in enumerate(vulnerabilities[:3], 1):
        print(f"\n--- Vulnerability {i}: {vuln.get('pn', 'Unknown')} ---")
        print(f"CVE: {vuln.get('c', 'None')}, CVSS: {vuln.get('cvss', 0.0)}")
        
        result = classifier.classify_vulnerability(vuln)
        
        classification = result["classification"]
        print(f"CWE: {classification['cwe']}")
        print(f"MITRE ATT&CK Tactics: {classification['mitre_attack'].get('tactics', [])}")
        print(f"MITRE ATT&CK Techniques: {classification['mitre_attack'].get('techniques', [])}")
        print(f"Exploitation Difficulty: {classification['exploitation_assessment'].get('difficulty', 'Unknown')}")
        print(f"Priority Score: {classification['priority_score']:.1f}/10")
        print(f"Classification Source: {classification['categorization_source']}")
        print(f"Confidence: {classification['confidence']:.2f}")
        print(f"Suggested Tools: {', '.join(classification['rl_agent_hints'].get('suggested_tools', []))}")
    
    # Print statistics
    print("\n" + "="*60)
    print("Classification Statistics:")
    print("="*60)
    stats = classifier.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")


def example_batch_classification():
    """Example 2: Batch classification with file output"""
    print("\n\n" + "="*60)
    print("Example 2: Batch Classification with File Output")
    print("="*60)
    
    input_file = "data/output/critical_ms2_scan.json"
    output_file = "data/output/classified_vulnerabilities.json"
    
    print(f"\nClassifying all vulnerabilities from {input_file}...")
    print(f"Output will be saved to {output_file}")
    
    # Use convenience function
    results = classify_from_file(
        input_file=input_file,
        output_file=output_file,
        mode="hybrid",  # Use hybrid mode (CVE lookup + pattern matching)
        enable_rag=False  # Disable RAG to avoid API calls in example
    )
    
    print(f"\n✓ Successfully classified {len(results)} vulnerabilities")
    print(f"✓ Output saved to {output_file}")


def example_single_vulnerability():
    """Example 3: Classify a single vulnerability (programmatic)"""
    print("\n\n" + "="*60)
    print("Example 3: Classify a Single Vulnerability")
    print("="*60)
    
    # Create a vulnerability dict programmatically
    vuln = {
        "id": "test_vuln_001",
        "h": "192.168.1.100",
        "p": 22,
        "s": 4,
        "pn": "SSH Server Weak Password",
        "c": "",
        "cvss": 9.0,
        "d": "The SSH server on the remote host is configured with a weak password that can be easily guessed.",
        "sol": "Configure a strong password policy and use SSH key authentication."
    }
    
    print("\nVulnerability:")
    print(json.dumps(vuln, indent=2))
    
    # Classify
    classifier = VulnerabilityClassifier(mode="hybrid")
    result = classifier.classify_vulnerability(vuln)
    
    print("\nClassification Result:")
    print(json.dumps(result, indent=2))


def example_rl_agent_integration():
    """Example 4: Show how an RL agent would use the classified data"""
    print("\n\n" + "="*60)
    print("Example 4: RL Agent Integration")
    print("="*60)
    
    # Load classified data
    input_file = "data/output/critical_ms2_scan.json"
    
    classifier = VulnerabilityClassifier(mode="hybrid")
    
    with open(input_file, 'r') as f:
        vulnerabilities = json.load(f)
    
    # Classify
    results = classifier.classify_batch(vulnerabilities[:5])
    
    # Simulate RL agent processing
    print("\nRL Agent Attack Simulation Plan:")
    print("="*60)
    
    # Sort by priority score
    results_sorted = sorted(results, key=lambda x: x["classification"]["priority_score"], reverse=True)
    
    for i, vuln in enumerate(results_sorted, 1):
        original = vuln["original"]
        classification = vuln["classification"]
        hints = classification["rl_agent_hints"]
        
        print(f"\n{i}. Priority {classification['priority_score']:.1f}/10")
        print(f"   Target: {original['h']}:{original['p']}")
        print(f"   Vulnerability: {original['pn']}")
        print(f"   Attack Type: {hints['attack_type']}")
        print(f"   Tools to Use: {', '.join(hints['suggested_tools'])}")
        print(f"   Validation Strategy: {hints['validation_strategy']}")
        print(f"   Expected Impact: {hints['expected_impact']}")
        print(f"   Next Steps:")
        for step in hints.get('next_steps', []):
            print(f"     - {step}")


def main():
    """Run all examples"""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*15 + "VULNERABILITY CLASSIFIER EXAMPLES" + " "*10 + "║")
    print("╚" + "="*58 + "╝")
    
    try:
        # Run examples
        example_basic_classification()
        example_batch_classification()
        example_single_vulnerability()
        example_rl_agent_integration()
        
        print("\n\n" + "="*60)
        print("All examples completed successfully!")
        print("="*60)
        print("\nNext steps:")
        print("1. Review the classified output in data/output/classified_vulnerabilities.json")
        print("2. Integrate with your RL agent using the rl_agent_hints fields")
        print("3. Customize patterns in Classifier/patterns.json for your environment")
        print("4. Enable RAG mode by setting OPENROUTER_API_KEY in .env")
        
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure you have run the parser first:")
        print("  python nessus_to_llm.py data/input/ms2_scan.nessus data/output/critical_ms2_scan.json")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
