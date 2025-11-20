#!/usr/bin/env python3
"""
Nessus Vulnerability Processor
Parses Nessus scan files, filters vulnerabilities, and outputs LLM-ready JSON
"""

import xml.etree.ElementTree as ET
import json
import sys
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from copy import deepcopy


class VulnProcessor:
    """Process Nessus vulnerability scans with flexible filtering"""
    
    def __init__(self, nessus_file: Optional[str] = None):
        """
        Initialize processor
        
        Args:
            nessus_file: Path to Nessus .nessus XML file (optional)
        """
        self.nessus_file = nessus_file
        self.data = {
            "scan_meta": {},
            "vulnerabilities": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            },
            "processing_status": {
                "critical": {"status": "pending", "processed_at": None},
                "high": {"status": "pending", "processed_at": None},
                "medium": {"status": "pending", "processed_at": None},
                "low": {"status": "pending", "processed_at": None},
                "info": {"status": "pending", "processed_at": None}
            }
        }
        self._filter_chain = []
        self._original_data = None
        self._id_counts = {}

        if nessus_file:
            self.parse()
    
    def parse(self, nessus_file: Optional[str] = None) -> 'VulnProcessor':
        """
        Parse Nessus XML file
        
        Args:
            nessus_file: Path to Nessus file (uses initialized file if not provided)
        
        Returns:
            Self for chaining
        """
        file_path = nessus_file or self.nessus_file
        if not file_path:
            raise ValueError("No Nessus file specified")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Extract scan metadata
            policy = root.find('.//Policy')
            report = root.find('.//Report')
            
            # Extract policy name safely
            policy_name = "Unknown"
            if policy is not None:
                policy_name_elem = policy.find('policyName')
                if policy_name_elem is not None and policy_name_elem.text:
                    policy_name = policy_name_elem.text
            
            self.data["scan_meta"] = {
                "scan_file": file_path,
                "scan_date": datetime.now().isoformat(),
                "policy_name": policy_name,
                "total_vulns": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            }
            
            # Find all report hosts
            report_hosts = root.findall('.//ReportHost')
            targets = []
            
            for report_host in report_hosts:
                host_name = report_host.get('name', 'Unknown')
                targets.append(host_name)
                
                # Find all vulnerabilities (ReportItems) for this host
                for item in report_host.findall('.//ReportItem'):
                    vuln = self._parse_report_item(item, host_name)
                    severity_level = self._get_severity_level(vuln['s'])
                    
                    # Add to appropriate severity bucket
                    self.data["vulnerabilities"][severity_level].append(vuln)
                    self.data["scan_meta"]["by_severity"][severity_level] += 1
                    self.data["scan_meta"]["total_vulns"] += 1
            
            self.data["scan_meta"]["targets"] = targets
            self._original_data = deepcopy(self.data)
            
            return self
            
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse Nessus XML: {e}")
        except Exception as e:
            raise RuntimeError(f"Error processing Nessus file: {e}")
    
    def _parse_report_item(self, item: ET.Element, host: str) -> Dict[str, Any]:
        """Parse a single ReportItem into vulnerability dict"""
        
        # Generate unique ID
        plugin_id = item.get('pluginID', '')
        port = item.get('port', '0')
        base_id = f"vuln_{host}_{port}_{plugin_id}"
        # Ensure uniqueness - if we have seen the same base_id, append a suffix
        if not hasattr(self, '_id_counts'):
            self._id_counts = {}
        count = self._id_counts.get(base_id, 0)
        if count > 0:
            vuln_id = f"{base_id}_{count}"
        else:
            vuln_id = base_id
        self._id_counts[base_id] = count + 1
        
        # Extract basic attributes
        severity = int(item.get('severity', '0'))
        
        # Extract child elements
        def get_text(tag: str) -> str:
            elem = item.find(tag)
            return elem.text if elem is not None and elem.text else ""
        
        # Extract CVE IDs
        cves = [cve.text for cve in item.findall('cve') if cve.text]
        cve_str = cves[0] if cves else ""
        
        # Extract CVSS score
        cvss_base = get_text('cvss_base_score')
        cvss_v3_base = get_text('cvss3_base_score')
        cvss = float(cvss_v3_base or cvss_base or 0.0)
        
        # Build vulnerability object (compact format)
        vuln = {
            "id": vuln_id,
            "h": host,
            "p": int(port),
            "s": severity,
            "pn": item.get('pluginName', ''),
            "pf": item.get('pluginFamily', ''),
            "c": cve_str,
            "cvss": cvss,
            "d": get_text('description'),
            "sol": get_text('solution'),
            "risk": get_text('risk_factor'),
            "proto": item.get('protocol', 'tcp'),
            "svc": item.get('svc_name', ''),
            "flags": [],
            "custom": {}
        }
        
        # Add additional CVEs if multiple
        if len(cves) > 1:
            vuln["cves"] = cves
        
        return vuln
    
    def _get_severity_level(self, severity: int) -> str:
        """Convert numeric severity to level name"""
        levels = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        return levels.get(severity, "info")
    
    # ==================== FILTERING METHODS ====================
    
    def severity(self, levels: List[int]) -> 'VulnProcessor':
        """
        Filter by severity levels
        
        Args:
            levels: List of severity levels (0-4)
        
        Returns:
            Self for chaining
        """
        self._filter_chain.append(("severity", {"levels": levels}))
        return self
    
    def ports(self, port_list: List[int]) -> 'VulnProcessor':
        """Include only specific ports"""
        self._filter_chain.append(("ports", {"ports": port_list}))
        return self
    
    def min_cvss(self, score: float) -> 'VulnProcessor':
        """Filter by minimum CVSS score"""
        self._filter_chain.append(("min_cvss", {"score": score}))
        return self
    
    def max_cvss(self, score: float) -> 'VulnProcessor':
        """Filter by maximum CVSS score"""
        self._filter_chain.append(("max_cvss", {"score": score}))
        return self
    
    def has_cve(self) -> 'VulnProcessor':
        """Include only vulnerabilities with CVE IDs"""
        self._filter_chain.append(("has_cve", {}))
        return self
    
    def family(self, families: List[str]) -> 'VulnProcessor':
        """Filter by plugin family"""
        self._filter_chain.append(("family", {"families": families}))
        return self
    
    def exclude_cve(self, cve: Union[str, List[str]]) -> 'VulnProcessor':
        """
        Exclude specific CVE(s)
        
        Args:
            cve: CVE ID or list of CVE IDs to exclude
        """
        cve_list = [cve] if isinstance(cve, str) else cve
        self._filter_chain.append(("exclude_cve", {"cves": cve_list}))
        return self
    
    def exclude(self, ports: Optional[List[int]] = None, 
                min_cvss: Optional[float] = None,
                max_cvss: Optional[float] = None,
                severity: Optional[List[int]] = None,
                except_if: Optional[Dict[str, Any]] = None) -> 'VulnProcessor':
        """
        Exclude vulnerabilities matching criteria, with conditional exceptions
        
        Args:
            ports: Exclude these ports
            min_cvss: Exclude if CVSS >= this
            max_cvss: Exclude if CVSS <= this
            severity: Exclude these severity levels
            except_if: Don't exclude if these conditions are met
                      Examples:
                      - {"family": ["Network", "Firewalls"]}
                      - {"severity": [4]}
                      - {"has_cve": True}
        
        Returns:
            Self for chaining
        """
        criteria = {
            "ports": ports,
            "min_cvss": min_cvss,
            "max_cvss": max_cvss,
            "severity": severity,
            "except_if": except_if
        }
        self._filter_chain.append(("exclude", criteria))
        return self
    
    def exclude_flags(self, flags: List[str]) -> 'VulnProcessor':
        """Exclude vulnerabilities with specific flags"""
        self._filter_chain.append(("exclude_flags", {"flags": flags}))
        return self
    
    def exclude_hosts(self, hosts: List[str]) -> 'VulnProcessor':
        """Exclude specific hosts"""
        self._filter_chain.append(("exclude_hosts", {"hosts": hosts}))
        return self
    
    def _apply_filters(self, vulns: List[Dict]) -> List[Dict]:
        """Apply all filters in chain to vulnerability list"""
        result = vulns.copy()
        
        for filter_type, criteria in self._filter_chain:
            if filter_type == "severity":
                result = [v for v in result if v['s'] in criteria['levels']]
            
            elif filter_type == "ports":
                result = [v for v in result if v['p'] in criteria['ports']]
            
            elif filter_type == "min_cvss":
                result = [v for v in result if v['cvss'] >= criteria['score']]
            
            elif filter_type == "max_cvss":
                result = [v for v in result if v['cvss'] <= criteria['score']]
            
            elif filter_type == "has_cve":
                result = [v for v in result if v['c']]
            
            elif filter_type == "family":
                result = [v for v in result if v['pf'] in criteria['families']]
            
            elif filter_type == "exclude_cve":
                result = [v for v in result if v['c'] not in criteria['cves']]
            
            elif filter_type == "exclude_flags":
                result = [v for v in result if not any(f in v['flags'] for f in criteria['flags'])]
            
            elif filter_type == "exclude_hosts":
                result = [v for v in result if v['h'] not in criteria['hosts']]
            
            elif filter_type == "exclude":
                result = self._apply_exclude_filter(result, criteria)
        
        return result
    
    def _apply_exclude_filter(self, vulns: List[Dict], criteria: Dict) -> List[Dict]:
        """Apply exclusion filter with except_if support"""
        result = []
        
        for v in vulns:
            # Check if vulnerability matches exclusion criteria
            should_exclude = False
            
            if criteria.get('ports') and v['p'] in criteria['ports']:
                should_exclude = True
            if criteria.get('min_cvss') and v['cvss'] >= criteria['min_cvss']:
                should_exclude = True
            if criteria.get('max_cvss') and v['cvss'] <= criteria['max_cvss']:
                should_exclude = True
            if criteria.get('severity') and v['s'] in criteria['severity']:
                should_exclude = True
            
            # Check except_if conditions
            if should_exclude and criteria.get('except_if'):
                except_if = criteria['except_if']
                
                # If any except_if condition matches, don't exclude
                if 'family' in except_if and v['pf'] in except_if['family']:
                    should_exclude = False
                if 'severity' in except_if and v['s'] in except_if['severity']:
                    should_exclude = False
                if 'has_cve' in except_if and except_if['has_cve'] and v['c']:
                    should_exclude = False
                if 'min_cvss' in except_if and v['cvss'] >= except_if['min_cvss']:
                    should_exclude = False
            
            if not should_exclude:
                result.append(v)
        
        return result
    
    # ==================== OUTPUT METHODS ====================
    
    def get(self) -> Dict[str, Any]:
        """
        Get filtered vulnerabilities (full format)
        
        Returns:
            Full vulnerability data structure
        """
        filtered_data = deepcopy(self.data)
        
        if self._filter_chain:
            # Apply filters to each severity level
            for level in ["critical", "high", "medium", "low", "info"]:
                filtered_data["vulnerabilities"][level] = self._apply_filters(
                    self.data["vulnerabilities"][level]
                )
            
            # Update metadata counts
            filtered_data["scan_meta"]["by_severity"] = {}
            total = 0
            for level in ["critical", "high", "medium", "low", "info"]:
                count = len(filtered_data["vulnerabilities"][level])
                filtered_data["scan_meta"]["by_severity"][level] = count
                total += count
            filtered_data["scan_meta"]["filtered_vulns"] = total
        
        return filtered_data
    
    def get_for_llm(self, fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get compact format for LLM processing (minimal tokens)
        
        Args:
            fields: Fields to include (default: essential fields only)
        
        Returns:
            List of compact vulnerability dicts
        """
        default_fields = ["id", "h", "p", "s", "pn", "c", "cvss", "d", "sol"]
        fields_to_include = fields or default_fields
        
        filtered_data = self.get()
        
        # Flatten all severity levels into single list
        all_vulns = []
        for level in ["critical", "high", "medium", "low", "info"]:
            all_vulns.extend(filtered_data["vulnerabilities"][level])
        
        # Filter to only requested fields
        compact = []
        for v in all_vulns:
            compact_vuln = {k: v[k] for k in fields_to_include if k in v}
            compact.append(compact_vuln)
        
        return compact
    
    def get_by_severity(self, level: str) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities by severity level
        
        Args:
            level: Severity level name (critical, high, medium, low, info)
        
        Returns:
            List of vulnerabilities at that level
        """
        filtered_data = self.get()
        return filtered_data["vulnerabilities"].get(level, [])
    
    # ==================== PARAMETER EXTENSION METHODS ====================
    
    def flag(self, flag_name: str, **criteria) -> 'VulnProcessor':
        """
        Add flag to vulnerabilities matching criteria
        
        Args:
            flag_name: Name of flag to add
            **criteria: Filter criteria (ports, min_cvss, severity, etc.)
        
        Returns:
            Self for chaining
        """
        # Apply filters to find matching vulnerabilities
        temp_processor = VulnProcessor()
        temp_processor.data = deepcopy(self.data)
        
        # Build filter chain from criteria
        if 'ports' in criteria:
            temp_processor.ports(criteria['ports'] if isinstance(criteria['ports'], list) else [criteria['ports']])
        if 'min_cvss' in criteria:
            temp_processor.min_cvss(criteria['min_cvss'])
        if 'severity' in criteria:
            temp_processor.severity(criteria['severity'] if isinstance(criteria['severity'], list) else [criteria['severity']])
        if 'family' in criteria:
            temp_processor.family(criteria['family'] if isinstance(criteria['family'], list) else [criteria['family']])
        
        # Get matching vulnerabilities and add flag
        filtered = temp_processor.get()
        matching_ids = set()
        for level in ["critical", "high", "medium", "low", "info"]:
            for v in filtered["vulnerabilities"][level]:
                matching_ids.add(v['id'])
        
        # Add flag to original data
        for level in ["critical", "high", "medium", "low", "info"]:
            for v in self.data["vulnerabilities"][level]:
                if v['id'] in matching_ids and flag_name not in v['flags']:
                    v['flags'].append(flag_name)
        
        return self
    
    def add_field(self, key: str, value: Any, **criteria) -> 'VulnProcessor':
        """
        Add custom field to vulnerabilities matching criteria
        
        Args:
            key: Field name
            value: Field value
            **criteria: Filter criteria
        
        Returns:
            Self for chaining
        """
        # Similar to flag(), but add custom field
        temp_processor = VulnProcessor()
        temp_processor.data = deepcopy(self.data)
        
        if 'ports' in criteria:
            temp_processor.ports(criteria['ports'] if isinstance(criteria['ports'], list) else [criteria['ports']])
        if 'min_cvss' in criteria:
            temp_processor.min_cvss(criteria['min_cvss'])
        if 'severity' in criteria:
            temp_processor.severity(criteria['severity'] if isinstance(criteria['severity'], list) else [criteria['severity']])
        if 'cve' in criteria:
            temp_processor._filter_chain.append(("match_cve", {"cve": criteria['cve']}))
        
        filtered = temp_processor.get()
        matching_ids = set()
        for level in ["critical", "high", "medium", "low", "info"]:
            for v in filtered["vulnerabilities"][level]:
                matching_ids.add(v['id'])
        
        for level in ["critical", "high", "medium", "low", "info"]:
            for v in self.data["vulnerabilities"][level]:
                if v['id'] in matching_ids:
                    v['custom'][key] = value
        
        return self
    
    def add_custom(self, data: Dict[str, Dict[str, Any]]) -> 'VulnProcessor':
        """
        Add custom data in bulk
        
        Args:
            data: Dict mapping vuln IDs to custom field dicts
                  Example: {"vuln_001": {"team": "infra", "priority": "P0"}}
        
        Returns:
            Self for chaining
        """
        for level in ["critical", "high", "medium", "low", "info"]:
            for v in self.data["vulnerabilities"][level]:
                if v['id'] in data:
                    v['custom'].update(data[v['id']])
        
        return self
    
    # ==================== SAVE/LOAD METHODS ====================
    
    def save(self, output_file: str) -> 'VulnProcessor':
        """
        Save to JSON file
        
        Args:
            output_file: Path to output file
        
        Returns:
            Self for chaining
        """
        data = self.get()
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        return self
    
    def load(self, input_file: str) -> 'VulnProcessor':
        """
        Load from JSON file
        
        Args:
            input_file: Path to input file
        
        Returns:
            Self for chaining
        """
        with open(input_file, 'r') as f:
            self.data = json.load(f)
        self._original_data = deepcopy(self.data)
        return self
    
    def to_json(self) -> str:
        """Return JSON string"""
        return json.dumps(self.get(), indent=2)
    
    def reset_filters(self) -> 'VulnProcessor':
        """Clear all filters"""
        self._filter_chain = []
        return self


# Convenience function for quick usage
def process_nessus(nessus_file: str, 
                   output_file: Optional[str] = None,
                   **filters) -> Union[VulnProcessor, None]:
    """
    Quick processing function
    
    Args:
        nessus_file: Path to Nessus file
        output_file: Optional output file
        **filters: Quick filters (severity, min_cvss, etc.)
    
    Returns:
        VulnProcessor instance or None if output_file specified
    """
    processor = VulnProcessor(nessus_file)
    
    if 'severity' in filters:
        processor.severity(filters['severity'])
    if 'min_cvss' in filters:
        processor.min_cvss(filters['min_cvss'])
    if 'ports' in filters:
        processor.ports(filters['ports'])
    
    if output_file:
        processor.save(output_file)
        return None
    
    return processor


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python nessus_to_llm.py <nessus_file> [output_file]")
        sys.exit(1)
    
    nessus_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    processor = VulnProcessor(nessus_file)
    
    if output_file:
        processor.save(output_file)
        print(f"Saved to {output_file}")
    else:
        print(processor.to_json())
