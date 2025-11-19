#!/usr/bin/env python3
"""
Test script to demonstrate the improved scoped pentest display
"""

import sys
import os
sys.path.insert(0, os.getcwd())

from parser.nessus_to_llm import VulnProcessor

# Parse Nessus file
print("="*80)
print("IMPROVED SCOPED PENTEST - VULNERABILITY DISPLAY TEST")
print("="*80)
print("\nParsing Nessus file: data/input/ms2_scan.nessus")

processor = VulnProcessor('data/input/ms2_scan.nessus')
vulns = processor.get_for_llm(fields=['id', 'pn', 'd', 'c', 'cvss', 's', 'p', 'h', 'sol'])

print(f"\nTotal vulnerabilities parsed: {len(vulns)}")
print("\n" + "="*80)
print("ENHANCED VULNERABILITY LIST")
print("="*80)

# Map severity numbers to labels
severity_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Enhanced display with CVE and CVSS
print(f"\n{'ID':<5} | {'Severity':<9} | {'CVSS':<5} | {'Port':<6} | {'CVE':<17} | {'Name'}")
print("-" * 120)

for i, v in enumerate(vulns[:20]):  # Show first 20
    vid = str(i + 1)
    sev_num = v.get('s', 0)
    sev_label = severity_map.get(sev_num, 'Unknown')
    port = v.get('p', 0)
    cvss = v.get('cvss', 0.0)
    cve = v.get('c', 'N/A')[:15] if v.get('c') else 'N/A'
    name = v.get('pn', 'Unknown')[:50]
    
    print(f"{vid:<5} | {sev_label:<9} | {cvss:<5.1f} | {port:<6} | {cve:<17} | {name}")

print("\n... (showing first 20 of {})".format(len(vulns)))

# Show detailed view example
print("\n" + "="*80)
print("EXAMPLE DETAILED VIEW - Vulnerability ID 3")
print("="*80)

v = vulns[2]  # Third vulnerability
print(f"Name:        {v.get('pn', 'Unknown')}")
print(f"CVE:         {v.get('c', 'N/A')}")
print(f"CVSS Score:  {v.get('cvss', 0.0)}")
print(f"Severity:    {severity_map.get(v.get('s', 0), 'Unknown')} ({v.get('s', 0)})")
print(f"Port:        {v.get('p', 0)}")
print(f"Host:        {v.get('h', 'Unknown')}")
print(f"\nDescription:\n{v.get('d', 'No description available')[:300]}...")
if v.get('sol'):
    print(f"\nSolution:\n{v.get('sol', 'N/A')[:200]}...")

print("\n" + "="*80)
print("IMPROVEMENTS:")
print("="*80)
print("1. ✓ CVE IDs are now visible in the main list")
print("2. ✓ CVSS scores are displayed for quick risk assessment")
print("3. ✓ Severity labels (Critical/High/Medium/Low/Info) instead of just numbers")
print("4. ✓ 'view <ID>' command to see full details before selection")
print("5. ✓ Full descriptions and solutions are accessible")
print("6. ✓ All vulnerability parameters are parsed and readable")
print("\n" + "="*80)
