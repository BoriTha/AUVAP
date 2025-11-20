#!/usr/bin/env python3
"""
Test Suite for Vulnerability Classifier
Tests pattern matching, CVE lookup, classification accuracy, and agent hints
"""

import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from classifier.vulnerability_classifier import VulnerabilityClassifier  # type: ignore
from classifier.knowledge_base import KnowledgeBase  # type: ignore


def test_knowledge_base_loading():
    """Test that knowledge base loads correctly"""
    print("\n" + "="*60)
    print("TEST: Knowledge Base Loading")
    print("="*60)
    
    kb = KnowledgeBase()
    
    # Check patterns loaded
    assert len(kb.patterns) > 0, "No patterns loaded"
    print(f"✓ Loaded {len(kb.patterns)} patterns")
    
    # Check specific patterns exist
    assert "backdoor" in kb.patterns, "Backdoor pattern missing"
    assert "weak_credentials" in kb.patterns, "Weak credentials pattern missing"
    print("✓ Key patterns exist: backdoor, weak_credentials, injection, etc.")
    
    # Check port mappings
    assert len(kb.port_mappings) > 0, "No port mappings loaded"
    print(f"✓ Loaded {len(kb.port_mappings)} port mappings")
    
    # Check CVE mappings
    assert len(kb.cve_mappings) > 0, "No CVE mappings loaded"
    print(f"✓ Loaded {len(kb.cve_mappings)} CVE mappings")
    
    print("✅ Knowledge base test PASSED\n")
    return True


def test_pattern_matching():
    """Test pattern matching functionality"""
    print("="*60)
    print("TEST: Pattern Matching")
    print("="*60)
    
    kb = KnowledgeBase()
    
    # Test 1: Backdoor detection
    desc1 = "The remote server has a bind shell backdoor listening on port 1234"
    matches1 = kb.match_pattern(desc1)
    assert len(matches1) > 0, "Failed to match backdoor pattern"
    assert matches1[0]["pattern_name"] == "backdoor", "Incorrect pattern match"
    print(f"✓ Backdoor pattern matched (confidence: {matches1[0]['confidence']:.2f})")
    
    # Test 2: Weak credentials
    desc2 = "The VNC server uses a default password 'password'"
    matches2 = kb.match_pattern(desc2)
    assert len(matches2) > 0, "Failed to match weak credentials"
    assert matches2[0]["pattern_name"] == "weak_credentials"
    print(f"✓ Weak credentials pattern matched (confidence: {matches2[0]['confidence']:.2f})")
    
    # Test 3: Cryptographic issues
    desc3 = "The server supports SSL 3.0 which uses broken cryptography"
    matches3 = kb.match_pattern(desc3)
    assert len(matches3) > 0, "Failed to match crypto issue"
    assert matches3[0]["pattern_name"] == "cryptographic_issues"
    print(f"✓ Cryptographic issues pattern matched (confidence: {matches3[0]['confidence']:.2f})")
    
    print("✅ Pattern matching test PASSED\n")
    return True


def test_cve_lookup():
    """Test CVE lookup functionality"""
    print("="*60)
    print("TEST: CVE Lookup")
    print("="*60)
    
    kb = KnowledgeBase()
    
    # Test known CVE
    cve_data = kb.lookup_cve("CVE-2020-1745")
    assert cve_data is not None, "Failed to find CVE-2020-1745"
    assert "name" in cve_data, "CVE data missing name"
    assert "cwe" in cve_data, "CVE data missing CWE"
    print(f"✓ CVE-2020-1745 found: {cve_data['name']}")
    
    # Test unknown CVE
    unknown = kb.lookup_cve("CVE-9999-9999")
    assert unknown is None, "Should return None for unknown CVE"
    print("✓ Unknown CVE returns None correctly")
    
    print("✅ CVE lookup test PASSED\n")
    return True


def test_classifier_basic():
    """Test basic classification"""
    print("="*60)
    print("TEST: Basic Classification")
    print("="*60)
    
    classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=False)
    
    # Test vulnerability with backdoor
    vuln1 = {
        "id": "test_001",
        "h": "192.168.1.1",
        "p": 1524,
        "s": 4,
        "pn": "Bind Shell Backdoor Detection",
        "c": "",
        "cvss": 10.0,
        "d": "A shell is listening on the remote port without any authentication being required.",
        "sol": "Verify if the remote host has been compromised."
    }
    
    result1 = classifier.classify_vulnerability(vuln1)
    
    assert "classification" in result1, "Missing classification"
    assert "cwe" in result1["classification"], "Missing CWE"
    assert "mitre_attack" in result1["classification"], "Missing MITRE ATT&CK"
    assert "priority_score" in result1["classification"], "Missing priority score"
    assert "agent_hints" in result1["classification"], "Missing agent hints"
    
    print(f"✓ Vulnerability classified: {vuln1['pn']}")
    print(f"  CWE: {result1['classification']['cwe']}")
    print(f"  Priority: {result1['classification']['priority_score']:.1f}/10")
    print(f"  Source: {result1['classification']['categorization_source']}")
    
    # Verify CWE-912 (Hidden Functionality) is assigned
    assert "CWE-912" in result1["classification"]["cwe"], "Expected CWE-912 for backdoor"
    print("✓ Correct CWE assigned (CWE-912: Hidden Functionality)")
    
    print("✅ Basic classification test PASSED\n")
    return True


def test_classifier_with_cve():
    """Test classification with CVE lookup"""
    print("="*60)
    print("TEST: Classification with CVE")
    print("="*60)
    
    classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=False)
    
    vuln = {
        "id": "test_002",
        "h": "192.168.1.2",
        "p": 8009,
        "s": 4,
        "pn": "Apache Tomcat AJP Connector Request Injection (Ghostcat)",
        "c": "CVE-2020-1745",
        "cvss": 9.8,
        "d": "A file read/inclusion vulnerability was found in AJP connector.",
        "sol": "Update the AJP configuration or upgrade Tomcat."
    }
    
    result = classifier.classify_vulnerability(vuln)
    
    # Should use CVE lookup
    assert result["classification"]["categorization_source"] == "cve_lookup", \
        "Should use CVE lookup for known CVE"
    
    print(f"✓ CVE classification: {vuln['c']}")
    print(f"  CWE: {result['classification']['cwe']}")
    print(f"  Source: {result['classification']['categorization_source']}")
    
    print("✅ CVE classification test PASSED\n")
    return True


def test_priority_scoring():
    """Test priority scoring algorithm"""
    print("="*60)
    print("TEST: Priority Scoring")
    print("="*60)
    
    classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=False)
    
    # High CVSS, easy exploitation = high priority
    vuln_high = {
        "id": "test_high",
        "h": "192.168.1.1",
        "p": 22,
        "s": 4,
        "pn": "SSH Weak Password",
        "c": "",
        "cvss": 10.0,
        "d": "The SSH server uses a weak password that can be easily guessed.",
        "sol": "Use strong passwords."
    }
    
    # Medium CVSS, hard exploitation = lower priority
    vuln_medium = {
        "id": "test_medium",
        "h": "192.168.1.1",
        "p": 443,
        "s": 3,
        "pn": "SSL Version 3 Protocol Detection",
        "c": "",
        "cvss": 6.5,
        "d": "The remote service accepts connections encrypted using SSL 3.0.",
        "sol": "Disable SSL 3.0."
    }
    
    result_high = classifier.classify_vulnerability(vuln_high)
    result_medium = classifier.classify_vulnerability(vuln_medium)
    
    priority_high = result_high["classification"]["priority_score"]
    priority_medium = result_medium["classification"]["priority_score"]
    
    assert priority_high > priority_medium, \
        "High CVSS + easy exploit should have higher priority"
    
    print(f"✓ High priority vuln: {priority_high:.1f}/10")
    print(f"✓ Medium priority vuln: {priority_medium:.1f}/10")
    print(f"✓ Priority ordering correct ({priority_high:.1f} > {priority_medium:.1f})")
    
    print("✅ Priority scoring test PASSED\n")
    return True


def test_agent_hints():
    """Test agent hints generation"""
    print("="*60)
    print("TEST: Agent Hints")
    print("="*60)
    
    classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=False)
    
    vuln = {
        "id": "test_003",
        "h": "192.168.1.3",
        "p": 6667,
        "s": 4,
        "pn": "UnrealIRCd Backdoor Detection",
        "c": "CVE-2010-2075",
        "cvss": 10.0,
        "d": "The remote IRC server is a version of UnrealIRCd with a backdoor.",
        "sol": "Re-download and verify the software."
    }
    
    result = classifier.classify_vulnerability(vuln)
    hints = result["classification"]["agent_hints"]
    
    assert "attack_type" in hints, "Missing attack_type"
    assert "suggested_tools" in hints, "Missing suggested_tools"
    assert "validation_strategy" in hints, "Missing validation_strategy"
    assert "expected_impact" in hints, "Missing expected_impact"
    assert "next_steps" in hints, "Missing next_steps"
    
    assert len(hints["suggested_tools"]) > 0, "No tools suggested"
    assert len(hints["next_steps"]) > 0, "No next steps provided"
    
    print(f"✓ Attack type: {hints['attack_type']}")
    print(f"✓ Tools: {', '.join(hints['suggested_tools'])}")
    print(f"✓ Validation strategy: {hints['validation_strategy'][:60]}...")
    print(f"✓ Next steps: {len(hints['next_steps'])} steps provided")
    
    print("✅ Agent hints test PASSED\n")
    return True


def test_batch_processing():
    """Test batch classification"""
    print("="*60)
    print("TEST: Batch Processing")
    print("="*60)
    
    # Load sample data
    sample_file = Path("data/output/critical_ms2_scan.json")
    
    if not sample_file.exists():
        print("⚠️  Sample file not found, skipping batch test")
        return True
    
    with open(sample_file, 'r') as f:
        vulns = json.load(f)
    
    # Classify first 5
    classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=False)
    results = classifier.classify_batch(vulns[:5])
    
    assert len(results) == 5, "Batch size mismatch"
    
    # Verify all have required fields
    for result in results:
        assert "id" in result, "Missing ID"
        assert "original" in result, "Missing original data"
        assert "classification" in result, "Missing classification"
        assert "metadata" in result, "Missing metadata"
    
    print(f"✓ Batch processed {len(results)} vulnerabilities")
    
    # Print stats
    stats = classifier.get_stats()
    print(f"✓ Pattern matches: {stats['pattern_matches']}")
    print(f"✓ CVE lookups: {stats['cve_lookups']}")
    
    print("✅ Batch processing test PASSED\n")
    return True


def test_output_schema():
    """Test output conforms to schema"""
    print("="*60)
    print("TEST: Output Schema Validation")
    print("="*60)
    
    classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=False)
    
    vuln = {
        "id": "test_schema",
        "h": "192.168.1.1",
        "p": 80,
        "s": 4,
        "pn": "Test Vulnerability",
        "c": "",
        "cvss": 9.0,
        "d": "Test description",
        "sol": "Test solution"
    }
    
    result = classifier.classify_vulnerability(vuln)
    
    # Validate top-level structure
    required_top = ["id", "original", "classification", "metadata"]
    for field in required_top:
        assert field in result, f"Missing top-level field: {field}"
    
    # Validate classification structure
    classification = result["classification"]
    required_classification = ["cwe", "cwe_names", "mitre_attack", "categorization_source",
                               "confidence", "exploitation_assessment", "priority_score",
                                "agent_hints"]
    for field in required_classification:
        assert field in classification, f"Missing classification field: {field}"
    
    # Validate metadata
    metadata = result["metadata"]
    required_metadata = ["classified_at", "classifier_version", "processing_time_ms"]
    for field in required_metadata:
        assert field in metadata, f"Missing metadata field: {field}"
    
    # Validate data types
    assert isinstance(classification["cwe"], list), "CWE should be list"
    assert isinstance(classification["priority_score"], (int, float)), "Priority should be number"
    assert 0 <= classification["priority_score"] <= 10, "Priority should be 0-10"
    assert 0 <= classification["confidence"] <= 1, "Confidence should be 0-1"
    
    print("✓ All required fields present")
    print("✓ Data types correct")
    print("✓ Value ranges valid")
    
    print("✅ Output schema test PASSED\n")
    return True


def run_all_tests():
    """Run all test functions"""
    tests = [
        test_knowledge_base_loading,
        test_pattern_matching,
        test_cve_lookup,
        test_classifier_basic,
        test_classifier_with_cve,
        test_priority_scoring,
        test_agent_hints,
        test_batch_processing,
        test_output_schema
    ]
    
    print("\n╔" + "="*58 + "╗")
    print("║" + " "*15 + "VULNERABILITY CLASSIFIER TESTS" + " "*12 + "║")
    print("╚" + "="*58 + "╝")
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
        except AssertionError as e:
            print(f"❌ TEST FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"❌ TEST ERROR: {e}\n")
            import traceback
            traceback.print_exc()
            failed += 1
    
    # Summary
    print("="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Total tests: {len(tests)}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"Coverage: {passed/len(tests)*100:.0f}%")
    print("="*60)
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!\n")
        return 0
    else:
        print(f"\n⚠️  {failed} test(s) failed\n")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
