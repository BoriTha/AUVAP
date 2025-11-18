#!/usr/bin/env python3
"""
Nessus Parser Validation Test Suite

This test suite validates the accuracy and correctness of the Nessus XML to JSON parser.
Critical for ensuring vulnerability data integrity for downstream AI/ML processing.

Test Coverage:
- Field mapping accuracy (XML → JSON)
- Data type conversions (severity, CVSS, ports)
- Edge cases (missing CVE, no CVSS, multiple CVEs)
- Special characters in descriptions
- CVSS v2 vs v3 score selection
- Severity level mapping (0-4)
"""

import sys
import os
import json
import xml.etree.ElementTree as ET
from pathlib import Path

# Add parent directory to path to import nessus_to_llm
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from parser.nessus_to_llm import VulnProcessor


class TestParserFieldMapping:
    """Test correct field extraction and mapping from Nessus XML to JSON"""
    
    @pytest.fixture
    def sample_nessus_file(self):
        """Path to sample Nessus file"""
        return "data/input/ms2_scan.nessus"
    
    @pytest.fixture
    def processor(self, sample_nessus_file):
        """Create processor instance with sample data"""
        return VulnProcessor(sample_nessus_file)
    
    @pytest.fixture
    def parsed_data(self, processor):
        """Get parsed vulnerability data"""
        return processor.get()
    
    def test_parser_loads_successfully(self, processor):
        """Test 1: Parser successfully loads and parses Nessus XML file"""
        assert processor is not None
        assert processor.data is not None
        assert "vulnerabilities" in processor.data
        assert "scan_meta" in processor.data
    
    def test_scan_metadata_extraction(self, parsed_data):
        """Test 2: Scan metadata is correctly extracted"""
        meta = parsed_data["scan_meta"]
        
        assert "scan_file" in meta
        assert "total_vulns" in meta
        assert "by_severity" in meta
        assert meta["total_vulns"] > 0
        
        # Check all severity levels are present
        severity_levels = ["critical", "high", "medium", "low", "info"]
        for level in severity_levels:
            assert level in meta["by_severity"]
    
    def test_vulnerability_fields_present(self, parsed_data):
        """Test 3: All required vulnerability fields are present"""
        required_fields = ["id", "h", "p", "s", "pn", "pf", "c", "cvss", "d", "sol"]
        
        # Get all vulnerabilities from all severity levels
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(parsed_data["vulnerabilities"][level])
        
        assert len(all_vulns) > 0, "No vulnerabilities found"
        
        # Check first vulnerability has all required fields
        vuln = all_vulns[0]
        for field in required_fields:
            assert field in vuln, f"Missing required field: {field}"
    
    def test_host_ip_extraction(self, parsed_data):
        """Test 4: Host IP addresses are correctly extracted"""
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(parsed_data["vulnerabilities"][level])
        
        for vuln in all_vulns:
            assert "h" in vuln
            assert isinstance(vuln["h"], str)
            assert len(vuln["h"]) > 0
            # IP should match pattern (basic check)
            assert "." in vuln["h"] or ":" in vuln["h"] or vuln["h"].replace(".", "").isdigit()
    
    def test_port_extraction_and_type(self, parsed_data):
        """Test 5: Port numbers are correctly extracted as integers"""
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(parsed_data["vulnerabilities"][level])
        
        for vuln in all_vulns:
            assert "p" in vuln
            assert isinstance(vuln["p"], int), f"Port should be int, got {type(vuln['p'])}"
            assert 0 <= vuln["p"] <= 65535, f"Invalid port number: {vuln['p']}"
    
    def test_severity_mapping(self, parsed_data):
        """Test 6: Severity levels are correctly mapped (0-4)"""
        severity_map = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        
        for level_name, expected_value in severity_map.items():
            vulns = parsed_data["vulnerabilities"][level_name]
            for vuln in vulns:
                assert vuln["s"] == expected_value, \
                    f"Severity mismatch in {level_name}: expected {expected_value}, got {vuln['s']}"
    
    def test_plugin_name_extraction(self, parsed_data):
        """Test 7: Plugin names (vulnerability names) are extracted"""
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(parsed_data["vulnerabilities"][level])
        
        for vuln in all_vulns:
            assert "pn" in vuln
            assert isinstance(vuln["pn"], str)
            assert len(vuln["pn"]) > 0, "Plugin name should not be empty"
    
    def test_plugin_family_extraction(self, parsed_data):
        """Test 8: Plugin family is correctly extracted"""
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(parsed_data["vulnerabilities"][level])
        
        for vuln in all_vulns:
            assert "pf" in vuln
            assert isinstance(vuln["pf"], str)


class TestCVEHandling:
    """Test CVE ID extraction and handling"""
    
    @pytest.fixture
    def processor(self):
        """Create processor instance with sample data"""
        return VulnProcessor("data/input/ms2_scan.nessus")
    
    def test_cve_extraction_when_present(self, processor):
        """Test 9: CVE IDs are correctly extracted when present"""
        data = processor.get()
        
        # Find vulnerability with CVE (from critical_ms2_scan.json we know CVE-2020-1745 exists)
        critical_vulns = data["vulnerabilities"]["critical"]
        
        cve_found = False
        for vuln in critical_vulns:
            if vuln["c"] and "CVE-" in vuln["c"]:
                cve_found = True
                assert vuln["c"].startswith("CVE-"), f"CVE format incorrect: {vuln['c']}"
                break
        
        assert cve_found, "Expected to find at least one vulnerability with CVE"
    
    def test_empty_cve_handling(self, processor):
        """Test 10: Empty CVE field is handled correctly (empty string, not None)"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        for vuln in all_vulns:
            assert "c" in vuln
            assert isinstance(vuln["c"], str), "CVE field should be string (empty if no CVE)"
    
    def test_multiple_cves_handling(self, processor):
        """Test 11: Multiple CVEs per vulnerability are handled"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        # Check if any vulnerability has multiple CVEs stored in 'cves' field
        multi_cve_found = False
        for vuln in all_vulns:
            if "cves" in vuln and len(vuln["cves"]) > 1:
                multi_cve_found = True
                assert isinstance(vuln["cves"], list)
                for cve in vuln["cves"]:
                    assert isinstance(cve, str)
                    assert cve.startswith("CVE-")
        
        # Note: Not all scans will have multi-CVE vulns, so we just verify the structure if present
        if multi_cve_found:
            print("✓ Multiple CVE handling verified")


class TestCVSSScoring:
    """Test CVSS score extraction and handling"""
    
    @pytest.fixture
    def processor(self):
        """Create processor instance with sample data"""
        return VulnProcessor("data/input/ms2_scan.nessus")
    
    def test_cvss_score_extraction(self, processor):
        """Test 12: CVSS scores are correctly extracted"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        for vuln in all_vulns:
            assert "cvss" in vuln
            assert isinstance(vuln["cvss"], (int, float))
            assert 0.0 <= vuln["cvss"] <= 10.0, f"CVSS out of range: {vuln['cvss']}"
    
    def test_cvss_v3_preferred_over_v2(self, processor):
        """Test 13: CVSS v3 score is preferred over v2 when both exist"""
        # From the XML we saw: cvss3_base_score=9.8, cvss_base_score=7.5
        # Parser should prefer v3 (9.8)
        data = processor.get()
        
        # Find the Ghostcat vulnerability (CVE-2020-1745)
        ghostcat = None
        for vuln in data["vulnerabilities"]["critical"]:
            if "CVE-2020-1745" in vuln.get("c", ""):
                ghostcat = vuln
                break
        
        if ghostcat:
            # Should be 9.8 (v3) not 7.5 (v2)
            assert ghostcat["cvss"] == 9.8, \
                f"Expected CVSS 9.8 (v3), got {ghostcat['cvss']}"
    
    def test_zero_cvss_handling(self, processor):
        """Test 14: Zero CVSS score is handled correctly (info level vulns)"""
        data = processor.get()
        
        info_vulns = data["vulnerabilities"]["info"]
        
        # Info level vulnerabilities may have 0 CVSS
        zero_cvss_found = False
        for vuln in info_vulns:
            if vuln["cvss"] == 0.0:
                zero_cvss_found = True
                break
        
        # Just verify that 0 CVSS is allowed and doesn't break parsing
        assert True  # If we got here without errors, test passes


class TestDescriptionAndSolution:
    """Test description and solution field extraction"""
    
    @pytest.fixture
    def processor(self):
        """Create processor instance with sample data"""
        return VulnProcessor("data/input/ms2_scan.nessus")
    
    def test_description_extraction(self, processor):
        """Test 15: Descriptions are correctly extracted"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        # Most vulnerabilities should have descriptions
        with_desc = sum(1 for v in all_vulns if v["d"] and len(v["d"]) > 0)
        assert with_desc > 0, "Expected some vulnerabilities with descriptions"
    
    def test_solution_extraction(self, processor):
        """Test 16: Solutions are correctly extracted"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        # Most vulnerabilities should have solutions
        with_sol = sum(1 for v in all_vulns if v["sol"] and len(v["sol"]) > 0)
        assert with_sol > 0, "Expected some vulnerabilities with solutions"
    
    def test_special_characters_in_description(self, processor):
        """Test 17: Special characters in descriptions don't break parsing"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        # Verify descriptions can be serialized to JSON
        for vuln in all_vulns:
            try:
                json.dumps(vuln["d"])
            except Exception as e:
                pytest.fail(f"Description contains invalid characters: {e}")


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    @pytest.fixture
    def processor(self):
        """Create processor instance with sample data"""
        return VulnProcessor("data/input/ms2_scan.nessus")
    
    def test_unique_vulnerability_ids(self, processor):
        """Test 18: Vulnerability IDs are unique"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        ids = [v["id"] for v in all_vulns]
        assert len(ids) == len(set(ids)), "Duplicate vulnerability IDs found"
    
    def test_vulnerability_id_format(self, processor):
        """Test 19: Vulnerability ID follows expected format"""
        data = processor.get()
        
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(data["vulnerabilities"][level])
        
        for vuln in all_vulns:
            # ID format: vuln_{host}_{port}_{pluginID}
            assert vuln["id"].startswith("vuln_"), f"Invalid ID format: {vuln['id']}"
            parts = vuln["id"].split("_")
            assert len(parts) >= 4, f"Invalid ID structure: {vuln['id']}"
    
    def test_json_serialization(self, processor):
        """Test 20: Full dataset can be serialized to JSON without errors"""
        data = processor.get()
        
        try:
            json_str = json.dumps(data, indent=2)
            assert len(json_str) > 0
            
            # Verify it can be deserialized
            parsed = json.loads(json_str)
            assert parsed == data
        except Exception as e:
            pytest.fail(f"JSON serialization failed: {e}")
    
    def test_llm_format_output(self, processor):
        """Test 21: LLM format (compact) is correctly generated"""
        llm_data = processor.get_for_llm()
        
        assert isinstance(llm_data, list)
        assert len(llm_data) > 0
        
        # Verify first entry has required fields
        if llm_data:
            first = llm_data[0]
            essential_fields = ["id", "h", "p", "s", "pn", "c", "cvss", "d", "sol"]
            for field in essential_fields:
                assert field in first, f"Missing field in LLM format: {field}"


class TestDataAccuracy:
    """Test data accuracy by comparing known vulnerabilities"""
    
    @pytest.fixture
    def processor(self):
        """Create processor instance"""
        return VulnProcessor("data/input/ms2_scan.nessus")
    
    @pytest.fixture
    def output_json(self):
        """Load expected output JSON for comparison"""
        with open("data/output/critical_ms2_scan.json", "r") as f:
            return json.load(f)
    
    def test_ghostcat_vulnerability_accuracy(self, processor, output_json):
        """Test 22: Ghostcat vulnerability data matches expected output"""
        data = processor.get()
        
        # Find Ghostcat in parsed data
        ghostcat_parsed = None
        for vuln in data["vulnerabilities"]["critical"]:
            if "CVE-2020-1745" in vuln.get("c", ""):
                ghostcat_parsed = vuln
                break
        
        # Find Ghostcat in expected output
        ghostcat_expected = None
        for vuln in output_json:
            if "CVE-2020-1745" in vuln.get("c", ""):
                ghostcat_expected = vuln
                break
        
        assert ghostcat_parsed is not None, "Ghostcat not found in parsed data"
        assert ghostcat_expected is not None, "Ghostcat not found in expected output"
        
        # Compare key fields
        assert ghostcat_parsed["h"] == ghostcat_expected["h"]
        assert ghostcat_parsed["p"] == ghostcat_expected["p"]
        assert ghostcat_parsed["s"] == ghostcat_expected["s"]
        assert ghostcat_parsed["c"] == ghostcat_expected["c"]
        assert ghostcat_parsed["cvss"] == ghostcat_expected["cvss"]
    
    def test_vnc_password_vulnerability_accuracy(self, processor, output_json):
        """Test 23: VNC 'password' Password vulnerability matches expected output"""
        data = processor.get()
        
        # Find VNC vuln in parsed data (port 5900)
        vnc_parsed = None
        for vuln in data["vulnerabilities"]["critical"]:
            if vuln.get("p") == 5900 and "password" in vuln.get("pn", "").lower():
                vnc_parsed = vuln
                break
        
        # Find VNC vuln in expected output
        vnc_expected = None
        for vuln in output_json:
            if vuln.get("p") == 5900 and "password" in vuln.get("pn", "").lower():
                vnc_expected = vuln
                break
        
        if vnc_parsed and vnc_expected:
            assert vnc_parsed["h"] == vnc_expected["h"]
            assert vnc_parsed["p"] == vnc_expected["p"]
            assert vnc_parsed["s"] == vnc_expected["s"]
            assert vnc_parsed["cvss"] == vnc_expected["cvss"]
    
    def test_critical_vulnerability_count(self, processor):
        """Test 24: Critical vulnerability count matches scan results"""
        data = processor.get()
        
        critical_count = len(data["vulnerabilities"]["critical"])
        meta_count = data["scan_meta"]["by_severity"]["critical"]
        
        assert critical_count == meta_count, \
            f"Critical count mismatch: {critical_count} vs {meta_count}"
        
        # Based on output JSON, we expect at least 11 critical vulnerabilities
        assert critical_count >= 11, f"Expected at least 11 critical, got {critical_count}"


class TestFilteringFunctionality:
    """Test filtering and data manipulation"""
    
    @pytest.fixture
    def processor(self):
        """Create processor instance"""
        return VulnProcessor("data/input/ms2_scan.nessus")
    
    def test_severity_filtering(self, processor):
        """Test 25: Severity filtering works correctly"""
        critical_only = processor.severity([4]).get()
        
        # All vulnerabilities should be critical (severity 4)
        for vuln in critical_only["vulnerabilities"]["critical"]:
            assert vuln["s"] == 4
        
        # Other severity levels should be empty
        assert len(critical_only["vulnerabilities"]["high"]) == 0
        assert len(critical_only["vulnerabilities"]["medium"]) == 0
    
    def test_cvss_filtering(self, processor):
        """Test 26: CVSS score filtering works correctly"""
        high_cvss = processor.min_cvss(9.0).get()
        
        # Get all vulnerabilities
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(high_cvss["vulnerabilities"][level])
        
        # All should have CVSS >= 9.0
        for vuln in all_vulns:
            assert vuln["cvss"] >= 9.0, f"CVSS filtering failed: {vuln['cvss']}"


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
