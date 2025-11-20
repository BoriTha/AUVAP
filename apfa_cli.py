#!/usr/bin/env python3
print("DEBUG: Starting apfa_cli.py")
"""
APFA - Unified CLI
Unified entry point for scanning, classification, and autonomous exploitation.
"""

import argparse
import sys
import os
import yaml
import json
import logging
from pathlib import Path
from datetime import datetime

class BackToMenu(Exception):
    """Raised when user wants to return to main menu"""
    pass

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger('apfa_cli')

# --- Path Setup ---
def setup_paths():
    """Ensure all project modules are importable"""
    root_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Add root
    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)
    
    # Add agent directory
    agent_dir = os.path.join(root_dir, 'apfa_agent')
    if agent_dir not in sys.path:
        sys.path.insert(0, agent_dir)
        
    # Add classifier directory
    classifier_dir = os.path.join(root_dir, 'classifier')
    if classifier_dir not in sys.path:
        sys.path.insert(0, classifier_dir)
        
    # Add parser directory
    parser_dir = os.path.join(root_dir, 'parser')
    if parser_dir not in sys.path:
        sys.path.insert(0, parser_dir)

setup_paths()

# --- Configuration ---
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'apfa_agent/config/agent_config.yaml')

def load_config(path=CONFIG_PATH):
    """Load configuration from YAML"""
    if not os.path.exists(path):
        logger.warning(f"Config file not found: {path}")
        return {}
    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        sys.exit(1)

def save_config(data, path=CONFIG_PATH):
    """Save configuration to YAML"""
    try:
        with open(path, 'w') as f:
            yaml.dump(data, f, sort_keys=False, default_flow_style=False)
        logger.info(f"Configuration updated: {path}")
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def banner():
    print(r"""
    ___    ____  _______  __   ________    ____
   /   |  / __ \/ ____/ |/ /  / ____/ /   /  _/
  / /| | / /_/ / /_  / /|_/  / /   / /    / /  
 / ___ |/ ____/ __/ / /  /  / /___/ /____/ /   
/_/  |_/_/   /_/   /_/  /_/ \____/_____/___/                                                
    AUVAP - Intelligent Pentesting CLI
    """)

# --- Lazy Imports ---
# We import inside commands or after setup to ensure paths are set

def get_nmap_scanner_class():
    try:
        from apfa_agent.core.nmap_scanner import NmapScanner
        return NmapScanner
    except ImportError as e:
        logger.error(f"Failed to import NmapScanner: {e}")
        sys.exit(1)

def get_classifier_classes():
    try:
        from classifier.vulnerability_classifier import VulnerabilityClassifier
        from parser.nessus_to_llm import VulnProcessor
        return VulnerabilityClassifier, VulnProcessor
    except ImportError as e:
        logger.error(f"Failed to import Classifier/Parser: {e}")
        sys.exit(1)

def get_agent_functions():
    try:
        from apfa_agent.agent_mode import SmartTriageAgent
        return SmartTriageAgent
    except ImportError as e:
        logger.error(f"Failed to import Agent: {e}")
        sys.exit(1)

# --- Command Handlers ---

def apply_vuln_filters(vulns, filters):
    """
    Apply filters to vulnerability list
    
    Supports:
    - Port filters: include_ports, exclude_ports
    - CVSS filters: cvss_min, cvss_max
    - Severity filters: include_severity, exclude_severity
    - Host filters: include_hosts, exclude_hosts
    - CVE filters: has_cve, exclude_cve
    - Exception conditions: except_if
    """
    result = vulns[:]
    
    for filter_def in filters:
        filtered = []
        
        for v in result:
            include = True
            
            # Extract vulnerability fields
            port = v.get('p', 0)
            cvss = v.get('cvss', 0.0)
            severity = v.get('s', 0)
            host = v.get('h', '')
            cve = v.get('c', '')
            
            # Apply include filters (if specified, only keep matching)
            if 'include_ports' in filter_def:
                include = include and (port in filter_def['include_ports'])
            
            if 'include_severity' in filter_def:
                include = include and (severity in filter_def['include_severity'])
            
            if 'include_hosts' in filter_def:
                include = include and (host in filter_def['include_hosts'])
            
            if 'cvss_min' in filter_def:
                include = include and (cvss >= filter_def['cvss_min'])
            
            if 'cvss_max' in filter_def:
                include = include and (cvss <= filter_def['cvss_max'])
            
            if 'has_cve' in filter_def and filter_def['has_cve']:
                include = include and bool(cve)
            
            # Apply exclude filters
            if include and 'exclude_ports' in filter_def:
                if port in filter_def['exclude_ports']:
                    include = False
                    
                    # Check exception conditions
                    if 'except_if' in filter_def:
                        exc = filter_def['except_if']
                        
                        if 'cvss_min' in exc and cvss >= exc['cvss_min']:
                            include = True
                        elif 'cvss_max' in exc and cvss <= exc['cvss_max']:
                            include = True
                        elif 'severity' in exc and severity in exc['severity']:
                            include = True
                        elif 'has_cve' in exc and exc['has_cve'] and cve:
                            include = True
            
            if include and 'exclude_severity' in filter_def:
                if severity in filter_def['exclude_severity']:
                    include = False
                    
                    # Check exception conditions
                    if 'except_if' in filter_def:
                        exc = filter_def['except_if']
                        if 'cvss_min' in exc and cvss >= exc['cvss_min']:
                            include = True
            
            if include and 'exclude_hosts' in filter_def:
                include = include and (host not in filter_def['exclude_hosts'])
            
            if include and 'exclude_cve' in filter_def:
                include = include and (cve != filter_def['exclude_cve'])
            
            if include:
                filtered.append(v)
        
        result = filtered
    
    return result

def handle_scoped_pentest(args):
    from apfa_agent.agent_mode import SmartTriageAgent
    print("\n>>> Scoped Pentest Mode (Interactive)")
    
    # 1. Select Input File
    if not args.input_file:
        # Auto-discover files in data/input
        input_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/input')
        available_files = []
        
        if os.path.exists(input_dir):
            print(f"\nLooking for scan files in: {input_dir}")
            for f in os.listdir(input_dir):
                if f.endswith(('.nessus', '.xml', '.json')) and not f.endswith('Zone.Identifier'):
                    available_files.append(f)
        
        if available_files:
            print("\nAvailable Scan Files:")
            for i, f in enumerate(available_files):
                print(f"{i+1}. {f}")
            print("0. Enter custom path")
            print("b. Back to menu")
            
            choice = input("\nSelect file [1-{}]: ".format(len(available_files))).strip()
            
            if choice.lower() in ['b', 'back', 'exit']:
                raise BackToMenu()
            elif choice == '0':
                args.input_file = get_user_input("Enter full path to scan file")
            elif choice.isdigit() and 0 < int(choice) <= len(available_files):
                args.input_file = os.path.join(input_dir, available_files[int(choice)-1])
            else:
                print("Invalid selection. Using manual entry.")
                args.input_file = get_user_input("Enter full path to scan file")
        else:
            print("No scan files found in data/input.")
            args.input_file = get_user_input("Enter full path to scan file")

        if not args.input_file:
            logger.error("Input file required.")
            return

    # 1. Load and Classify (reuse handle_classify logic or simplified)
    VulnerabilityClassifier, VulnProcessor = get_classifier_classes()
    
    vulns = []
    input_path = args.input_file
    if not os.path.exists(input_path):
        logger.error(f"File not found: {input_path}")
        return

    try:
        if input_path.endswith('.nessus'):
            print(f"Parsing Nessus file: {input_path}")
            processor = VulnProcessor(input_path)
            vulns = processor.get_for_llm(fields=["id", "pn", "d", "c", "cvss", "s", "p", "h", "plugin_name", "description", "sol"])
            print(f"Successfully parsed {len(vulns)} vulnerabilities from Nessus file")
        elif input_path.endswith('.xml'):
            print(f"Parsing Nmap XML file: {input_path}")
            # For Nmap XML, we need to convert it to vulnerability format
            # This is a simplified version - Nmap doesn't have vulns like Nessus
            # We'll create synthetic vulnerability records from open ports
            import xml.etree.ElementTree as ET
            tree = ET.parse(input_path)
            root = tree.getroot()
            
            vulns = []
            for host in root.findall('.//host'):
                addr_elem = host.find('.//address[@addrtype="ipv4"]')
                if addr_elem is None:
                    continue
                ip_addr = addr_elem.get('addr', 'unknown')
                
                for port_elem in host.findall('.//port'):
                    state = port_elem.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_num = int(port_elem.get('portid', 0))
                        service = port_elem.find('service')
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        service_product = service.get('product', '') if service is not None else ''
                        service_version = service.get('version', '') if service is not None else ''
                        
                        # Create a synthetic vulnerability record for each open port
                        vuln = {
                            'id': f'nmap_{ip_addr}_{port_num}',
                            'h': ip_addr,
                            'p': port_num,
                            's': 1,  # Low severity by default (just open port)
                            'pn': f'{service_name} Service Detection',
                            'c': '',
                            'cvss': 0.0,
                            'd': f'Open port detected: {port_num}/{service_name}. Product: {service_product} {service_version}',
                            'sol': 'Review if this service should be exposed'
                        }
                        vulns.append(vuln)
            
            print(f"Successfully parsed {len(vulns)} open ports from Nmap XML file")
            if len(vulns) == 0:
                print("Warning: No open ports found in Nmap scan. Make sure the XML file is valid.")
                logger.warning("No vulnerabilities found in XML file")
                return
        elif input_path.endswith('.json'):
            print(f"Loading JSON file: {input_path}")
            with open(input_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    vulns = data
                elif isinstance(data, dict) and 'vulnerabilities' in data:
                    for sev in data['vulnerabilities']:
                        vulns.extend(data['vulnerabilities'][sev])
                elif isinstance(data, dict):
                    vulns = [data]
            print(f"Successfully loaded {len(vulns)} vulnerabilities from JSON file")
        else:
            logger.error(f"Unsupported file format: {input_path}")
            logger.error("Supported formats: .nessus, .xml (Nmap), .json")
            return
    except Exception as e:
        logger.error(f"Failed to load: {e}")
        import traceback
        traceback.print_exc()
        return

    # Classify (if needed) - Assuming we want enriched data for decision making
    # If loading from raw nessus, we should probably run classifier.
    # For speed, maybe skip full classification if just selecting? 
    # Prompt says: "Run VulnerabilityClassifier to find pentestable candidates."
    classifier = VulnerabilityClassifier(enable_rag=False)
    print("Classifying candidates...")
    classified_results = classifier.classify_batch(vulns)
    
    # Extract original vulnerability data from classification results
    # Classifier returns: {"id": ..., "original": vuln_data, "classification": ..., "metadata": ...}
    vulns = []
    for result in classified_results:
        if isinstance(result, dict) and 'original' in result:
            # Extract original vuln and merge with classification if needed
            vuln = result['original']
            # Optionally add classification data for display
            if 'classification' in result:
                vuln['_classification'] = result['classification']
            vulns.append(vuln)
        else:
            # Fallback if structure is different
            vulns.append(result)
    
    # Store original unfiltered list
    all_vulns = vulns[:]
    active_filters = []

    # 2. Interactive Selection - Enhanced with better display and filtering
    while True:  # Loop to allow viewing details and filtering before selection
        print("\n--- Candidate Vulnerabilities ---")
        print(f"Total vulnerabilities found: {len(vulns)}\n")
        
        # Map severity numbers to labels
        severity_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        
        # Store map for easy retrieval
        vuln_map = {}
        display_list = []
        
        # Enhanced display with CVE and CVSS
        print(f"{'ID':<5} | {'Severity':<9} | {'CVSS':<5} | {'Port':<6} | {'CVE':<17} | {'Name'}")
        print("-" * 120)
        
        for i, v in enumerate(vulns):
            vid = str(i + 1)
            vuln_map[vid] = v
            sev_num = v.get('s', 0)
            sev_label = severity_map.get(sev_num, 'Unknown')
            port = v.get('p', 0)
            cvss = v.get('cvss', 0.0)
            cve = v.get('c', 'N/A')[:15] if v.get('c') else 'N/A'
            name = v.get('pn', 'Unknown')[:50]
            
            print(f"{vid:<5} | {sev_label:<9} | {cvss:<5.1f} | {port:<6} | {cve:<17} | {name}")
            display_list.append(vid)

        print("-" * 120)
        
        # Show active filters
        if active_filters:
            print("\n🔍 Active Filters:")
            for i, f in enumerate(active_filters, 1):
                filter_desc = []
                if 'include_ports' in f:
                    filter_desc.append(f"Include ports: {f['include_ports']}")
                if 'exclude_ports' in f:
                    filter_desc.append(f"Exclude ports: {f['exclude_ports']}")
                if 'cvss_min' in f:
                    filter_desc.append(f"CVSS >= {f['cvss_min']}")
                if 'cvss_max' in f:
                    filter_desc.append(f"CVSS <= {f['cvss_max']}")
                if 'include_severity' in f:
                    sevs = [str(severity_map.get(s, s)) for s in f['include_severity']]
                    filter_desc.append(f"Severity: {', '.join(sevs)}")
                if 'exclude_severity' in f:
                    sevs = [str(severity_map.get(s, s)) for s in f['exclude_severity']]
                    filter_desc.append(f"Exclude severity: {', '.join(sevs)}")
                if 'has_cve' in f:
                    filter_desc.append("Has CVE")
                if 'except_if' in f:
                    filter_desc.append(f"EXCEPT IF: {f['except_if']}")
                print(f"  {i}. {' | '.join(filter_desc)}")
            print(f"  ({len(all_vulns)} total → {len(vulns)} after filters)")
        
        print("\nCommands:")
        print("  Selection:")
        print("    - Enter IDs (comma-separated): e.g., '1,3,5'")
        print("    - 'all': Select all displayed vulnerabilities")
        print("    - 'view <ID>': View full details (e.g., 'view 1')")
        print("\n  Filtering:")
        print("    - 'filter port <ports>': Include only ports (e.g., 'filter port 80,443,22')")
        print("    - 'exclude port <ports>': Exclude ports (e.g., 'exclude port 8080,3000')")
        print("    - 'filter cvss <min> <max>': Filter by CVSS range (e.g., 'filter cvss 7 10')")
        print("    - 'filter cvss > <value>': CVSS greater than (e.g., 'filter cvss > 8')")
        print("    - 'filter cvss < <value>': CVSS less than (e.g., 'filter cvss < 5')")
        print("    - 'filter severity <levels>': critical,high,medium,low,info")
        print("    - 'filter cve': Only show vulnerabilities with CVE")
        print("    - 'except port <port> if cvss > <val>': Exclude port EXCEPT if CVSS high")
        print("    - 'reset': Clear all filters")
        print("    - 'b': Back to menu")
        
        selection = input("\n> ").strip()
        
        # Handle filter commands
        if selection.lower().startswith('filter port '):
            try:
                ports_str = selection.split('filter port ')[1]
                ports = [int(p.strip()) for p in ports_str.split(',')]
                active_filters.append({'include_ports': ports})
                vulns = apply_vuln_filters(all_vulns, active_filters)
                print(f"✓ Applied port filter: {ports}")
                input("Press Enter to continue...")
                continue
            except:
                print("Usage: filter port <port1>,<port2>,...")
                input("Press Enter to continue...")
                continue
        
        if selection.lower().startswith('exclude port '):
            # Check for exception conditions
            if ' if cvss > ' in selection.lower():
                try:
                    parts = selection.split(' if cvss > ')
                    ports_str = parts[0].split('exclude port ')[1]
                    ports = [int(p.strip()) for p in ports_str.split(',')]
                    cvss_threshold = float(parts[1].strip())
                    active_filters.append({
                        'exclude_ports': ports,
                        'except_if': {'cvss_min': cvss_threshold}
                    })
                    vulns = apply_vuln_filters(all_vulns, active_filters)
                    print(f"✓ Applied: Exclude ports {ports} EXCEPT if CVSS >= {cvss_threshold}")
                    input("Press Enter to continue...")
                    continue
                except:
                    print("Usage: except port <port> if cvss > <value>")
                    input("Press Enter to continue...")
                    continue
            elif ' if severity ' in selection.lower():
                try:
                    parts = selection.split(' if severity ')
                    ports_str = parts[0].split('exclude port ')[1]
                    ports = [int(p.strip()) for p in ports_str.split(',')]
                    sev_str = parts[1].strip().lower()
                    sev_map_rev = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                    severities = [sev_map_rev.get(s.strip(), 0) for s in sev_str.split(',')]
                    active_filters.append({
                        'exclude_ports': ports,
                        'except_if': {'severity': severities}
                    })
                    vulns = apply_vuln_filters(all_vulns, active_filters)
                    print(f"✓ Applied: Exclude ports {ports} EXCEPT if severity in {sev_str}")
                    input("Press Enter to continue...")
                    continue
                except:
                    print("Usage: exclude port <port> if severity <critical,high,...>")
                    input("Press Enter to continue...")
                    continue
            else:
                try:
                    ports_str = selection.split('exclude port ')[1]
                    ports = [int(p.strip()) for p in ports_str.split(',')]
                    active_filters.append({'exclude_ports': ports})
                    vulns = apply_vuln_filters(all_vulns, active_filters)
                    print(f"✓ Applied port exclusion: {ports}")
                    input("Press Enter to continue...")
                    continue
                except:
                    print("Usage: exclude port <port1>,<port2>,...")
                    input("Press Enter to continue...")
                    continue
        
        if selection.lower().startswith('filter cvss'):
            try:
                if ' > ' in selection:
                    min_cvss = float(selection.split(' > ')[1].strip())
                    active_filters.append({'cvss_min': min_cvss})
                    print(f"✓ Applied CVSS filter: >= {min_cvss}")
                elif ' < ' in selection:
                    max_cvss = float(selection.split(' < ')[1].strip())
                    active_filters.append({'cvss_max': max_cvss})
                    print(f"✓ Applied CVSS filter: <= {max_cvss}")
                else:
                    parts = selection.split('filter cvss ')[1].split()
                    min_cvss = float(parts[0])
                    max_cvss = float(parts[1]) if len(parts) > 1 else 10.0
                    active_filters.append({'cvss_min': min_cvss, 'cvss_max': max_cvss})
                    print(f"✓ Applied CVSS filter: {min_cvss} - {max_cvss}")
                vulns = apply_vuln_filters(all_vulns, active_filters)
                input("Press Enter to continue...")
                continue
            except:
                print("Usage: filter cvss <min> <max> OR filter cvss > <val> OR filter cvss < <val>")
                input("Press Enter to continue...")
                continue
        
        if selection.lower().startswith('filter severity '):
            try:
                sev_str = selection.split('filter severity ')[1].strip().lower()
                sev_map_rev = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
                severities = [sev_map_rev.get(s.strip(), 0) for s in sev_str.split(',')]
                active_filters.append({'include_severity': severities})
                vulns = apply_vuln_filters(all_vulns, active_filters)
                print(f"✓ Applied severity filter: {sev_str}")
                input("Press Enter to continue...")
                continue
            except:
                print("Usage: filter severity <critical,high,medium,low,info>")
                input("Press Enter to continue...")
                continue
        
        if selection.lower() == 'filter cve':
            active_filters.append({'has_cve': True})
            vulns = apply_vuln_filters(all_vulns, active_filters)
            print("✓ Applied filter: Only vulnerabilities with CVE")
            input("Press Enter to continue...")
            continue
        
        if selection.lower() == 'reset':
            active_filters = []
            vulns = all_vulns[:]
            print("✓ All filters cleared")
            input("Press Enter to continue...")
            continue
        
        # Handle 'view' command
        if selection.lower().startswith('view '):
            try:
                view_id = selection.split()[1].strip()
                if view_id in vuln_map:
                    v = vuln_map[view_id]
                    print("\n" + "="*80)
                    print(f"Vulnerability Details - ID: {view_id}")
                    print("="*80)
                    print(f"Name:        {v.get('pn', 'Unknown')}")
                    print(f"CVE:         {v.get('c', 'N/A')}")
                    print(f"CVSS Score:  {v.get('cvss', 0.0)}")
                    print(f"Severity:    {severity_map.get(v.get('s', 0), 'Unknown')} ({v.get('s', 0)})")
                    print(f"Port:        {v.get('p', 0)}")
                    print(f"Host:        {v.get('h', 'Unknown')}")
                    print(f"\nDescription:\n{v.get('d', 'No description available')}")
                    if v.get('sol'):
                        print(f"\nSolution:\n{v.get('sol')}")
                    print("="*80)
                    input("\nPress Enter to continue...")
                else:
                    print(f"Invalid ID: {view_id}")
                    input("Press Enter to continue...")
            except IndexError:
                print("Usage: view <ID>")
                input("Press Enter to continue...")
            continue
        
        # Break out of loop if valid selection or back command
        break
    
    if selection.lower() in ['b', 'back', 'exit']:
        raise BackToMenu()

    selected_vulns = []
    if selection.lower() == 'all':
        selected_vulns = vulns
    else:
        ids = [x.strip() for x in selection.split(',')]
        for i in ids:
            if i in vuln_map:
                selected_vulns.append(vuln_map[i])
    
    if not selected_vulns:
        print("No targets selected. Aborting.")
        return

    # 3. Extract Ports, Hosts, and Save Scope
    scope_ports = sorted(list(set(int(v.get('p', 0)) for v in selected_vulns if v.get('p', 0))))
    
    # Extract unique target IPs from selected vulnerabilities
    target_hosts = sorted(list(set(v.get('h', '') for v in selected_vulns if v.get('h', ''))))
    
    print(f"\nScoped Ports: {scope_ports}")
    print(f"Target Host(s): {', '.join(target_hosts) if target_hosts else 'None detected'}")
    
    scope_data = {
        'ports': scope_ports,
        'hosts': target_hosts,
        'vulnerabilities': selected_vulns,
        'created_at': datetime.now().isoformat()
    }
    
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/temp')
    os.makedirs(temp_dir, exist_ok=True)
    scope_path = os.path.join(temp_dir, 'scope.json')
    
    with open(scope_path, 'w') as f:
        json.dump(scope_data, f, indent=2)
    print(f"Scope saved to: {scope_path}")

    # 4. Launch Agent
    # We need to call agent mode with this scope
    SmartTriageAgent = get_agent_functions()
    config = load_config()
    
    # Determine target IP - prioritize: args > extracted from vulns > config > user input
    target = args.target
    
    if not target and target_hosts:
        # Use the first target host from the vulnerabilities
        target = target_hosts[0]
        print(f"\nAuto-detected target IP from scan data: {target}")
        if len(target_hosts) > 1:
            print(f"Note: Multiple hosts detected: {', '.join(target_hosts)}")
            confirm = input(f"Use {target} as primary target? (y/n): ").strip().lower()
            if confirm != 'y':
                target = get_user_input("Enter Target IP", target_hosts[0])
    
    if not target:
        target = config.get('target', {}).get('ip')
    
    if not target:
        target = get_user_input("Enter Target IP")
    
    if 'target' not in config: config['target'] = {}
    config['target']['ip'] = target

    print("\n>>> Launching Scoped Agent...")
    # Use SmartTriageAgent with scope data
    try:
        agent = SmartTriageAgent(config_path=CONFIG_PATH, config=config)
        agent.run(classified_json_path=scope_path, nmap_results=None)
    except Exception as e:
        logger.error(f"Scoped agent failed: {e}")
        import traceback
        traceback.print_exc()
        return

def handle_setup(args):
    print("\n--- Interactive Setup ---")
    if args.dry_run:
        print("[Dry Run] Would open interactive configuration.")
        return

    config = load_config()
    
    # Target Configuration
    current_target = config.get('target', {}).get('ip', '')
    print(f"Current default target: {current_target}")
    new_target = input("Enter new target IP (or press Enter to keep): ").strip()
    
    if new_target:
        if 'target' not in config: config['target'] = {}
        config['target']['ip'] = new_target
        print(f"Target updated to: {new_target}")
    
    # API Configuration (Basic)
    print("\n--- API Configuration ---")
    print("To configure LLM API keys, ensure environment variables are set.")
    print("Examples: OPENROUTER_API_KEY, OPENAI_API_KEY")
    
    # Save
    save_config(config)
    print("Setup complete.")

def handle_scan(args):
    print("\n>>> Scan Mode")
    
    config = load_config()
    
    # Override target
    if args.target:
        if 'target' not in config: config['target'] = {}
        config['target']['ip'] = args.target
        
    target = config.get('target', {}).get('ip')
    if not target:
        logger.error("Error: No target specified in args or config.")
        sys.exit(1)
        
    if args.dry_run:
        print(f"[Dry Run] Would run Nmap scan against {target}")
        return

    NmapScanner = get_nmap_scanner_class()
    
    try:
        print(f"Initializing scanner for target: {target}")
        scanner = NmapScanner(config)
        print("Starting scan... (this may take a while)")
        results = scanner.scan(target)
        
        open_ports = len(results.get('open_ports', [])) if isinstance(results.get('open_ports'), list) else 0
        # Check structure of results (NmapScanner returns parsed dict)
        # Actually NmapScanner.scan returns dict with 'hosts'.
        # Let's trust the scanner's logging.
        print("Scan complete.")
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

def handle_classify(args):
    print("\n>>> Classify Mode")
    
    VulnerabilityClassifier, VulnProcessor = get_classifier_classes()
    
    # Handle init-config
    if args.init_config:
        if args.dry_run:
            print("[Dry Run] Would generate config template")
            return
        cls = VulnerabilityClassifier(enable_rag=False)
        print(cls.generate_config_template())
        return

    if not args.input_file:
        logger.error("Error: Input file required for classification.")
        sys.exit(1)

    if args.dry_run:
        print(f"[Dry Run] Would classify {args.input_file}")
        return

    # Load and Parse
    vulns = []
    input_path = args.input_file
    
    if not os.path.exists(input_path):
        logger.error(f"File not found: {input_path}")
        sys.exit(1)

    try:
        if input_path.endswith('.nessus'):
            print(f"Parsing Nessus file: {input_path}")
            processor = VulnProcessor(input_path)
            # Get fields compatible with classifier - include 'sol' for solution info
            vulns = processor.get_for_llm(fields=["id", "pn", "d", "c", "cvss", "s", "p", "h", "plugin_name", "description", "sol"])
            print(f"Successfully parsed {len(vulns)} vulnerabilities")
        elif input_path.endswith('.xml'):
            print(f"Parsing Nmap XML file: {input_path}")
            # Convert Nmap XML to vulnerability format
            import xml.etree.ElementTree as ET
            tree = ET.parse(input_path)
            root = tree.getroot()
            
            vulns = []
            for host in root.findall('.//host'):
                addr_elem = host.find('.//address[@addrtype="ipv4"]')
                if addr_elem is None:
                    continue
                ip_addr = addr_elem.get('addr', 'unknown')
                
                for port_elem in host.findall('.//port'):
                    state = port_elem.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_num = int(port_elem.get('portid', 0))
                        service = port_elem.find('service')
                        service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                        service_product = service.get('product', '') if service is not None else ''
                        service_version = service.get('version', '') if service is not None else ''
                        
                        # Create a synthetic vulnerability record for each open port
                        vuln = {
                            'id': f'nmap_{ip_addr}_{port_num}',
                            'h': ip_addr,
                            'p': port_num,
                            's': 1,  # Low severity by default
                            'pn': f'{service_name} Service Detection',
                            'c': '',
                            'cvss': 0.0,
                            'd': f'Open port: {port_num}/{service_name}. Product: {service_product} {service_version}',
                            'sol': 'Review if this service should be exposed'
                        }
                        vulns.append(vuln)
            
            print(f"Successfully parsed {len(vulns)} open ports from Nmap XML")
        elif input_path.endswith('.json'):
            print(f"Loading JSON file: {input_path}")
            with open(input_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    vulns = data
                elif isinstance(data, dict) and 'vulnerabilities' in data:
                    # Handle processor output format
                    for sev in data['vulnerabilities']:
                        vulns.extend(data['vulnerabilities'][sev])
                elif isinstance(data, dict):
                    vulns = [data]
            print(f"Successfully loaded {len(vulns)} vulnerabilities from JSON")
        else:
            logger.error("Unknown file format. Supported: .nessus, .xml (Nmap), .json")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Failed to load/parse input: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Apply Filters
    filters = {}
    if args.config:
        if os.path.exists(args.config):
            print(f"Loading filters from: {args.config}")
            with open(args.config, 'r') as f:
                filters = yaml.safe_load(f)
        else:
            logger.warning(f"Filter config not found: {args.config}")
    
    classifier = VulnerabilityClassifier(enable_rag=False) # RAG off by default for CLI unless flag? 
    # Prompt didn't specify RAG flag for classify command, but good to have.
    # We'll assume False for speed unless we add a flag.
    
    if filters:
        print("Applying filters...")
        initial_count = len(vulns)
        vulns = classifier.apply_filters(vulns, filters)
        print(f"Filtered: {initial_count} -> {len(vulns)} vulnerabilities")

    # Classify
    print(f"Classifying {len(vulns)} vulnerabilities...")
    results = classifier.classify_batch(vulns)
    
    # Save
    output_path = args.output
    if not output_path:
        base = os.path.splitext(os.path.basename(input_path))[0]
        output_path = f"{base}_classified.json"
        
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
        
    print(f"Results saved to: {output_path}")
    return output_path

def handle_attack(args):
    from apfa_agent.agent_mode import SmartTriageAgent
    print("\n>>> Attack Mode")
    
    SmartTriageAgent = get_agent_functions()
    
    config = load_config()
    
    target = args.target or config.get('target', {}).get('ip')
    if not target:
        logger.error("Error: Target IP required (arg or config).")
        sys.exit(1)
        
    # Override config target
    if 'target' not in config: config['target'] = {}
    config['target']['ip'] = target
    
    if args.dry_run:
        print(f"[Dry Run] Would launch LLM-based attack on {target}")
        return

    print(f"Target: {target}")
    print("Mode: Intelligent Smart Triage")
    
    try:
        print("Starting Intelligent Smart Triage...")
        agent = SmartTriageAgent(config_path=CONFIG_PATH, config=config)
        agent.run(classified_json_path=args.input_file, nmap_results=None)
            
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def handle_workflow(args):
    print(f"\n>>> Workflow: {args.type.upper()}")
    
    if args.type == 'ingest':
        # Ingest -> Classify
        if not args.nessus_file:
            logger.error("Error: --nessus-file required for ingest workflow")
            sys.exit(1)
            
        print("\n[Step 1/1] Processing and Classifying...")
        cls_args = argparse.Namespace(
            input_file=args.nessus_file,
            output=None,
            config=None,
            init_config=False,
            dry_run=args.dry_run
        )
        handle_classify(cls_args)
    else:
        logger.error(f"Unsupported workflow type: {args.type}. Only 'ingest' workflow is available.")
        sys.exit(1)


def get_user_input(prompt_text, default_value=None, allow_back=True):
    """Helper to get input with default value and back navigation"""
    prompt = f"{prompt_text}"
    if default_value:
        prompt += f" [{default_value}]"
    
    if allow_back:
        prompt += " (b to back)"
    
    prompt += ": "
    
    try:
        value = input(prompt).strip()
    except EOFError:
        return default_value if default_value else ""

    if allow_back and value.lower() in ['b', 'back', 'return', 'exit']:
        raise BackToMenu()

    if not value and default_value:
        return default_value
    return value

def interactive_menu():
    """Main interactive menu loop"""
    while True:
        try:
            banner()
            print("1. Setup (Configure Target/API)")
            print("2. Scan (Run Nmap)")
            print("3. Classify (Process Scan Data)")
            print("4. Attack (Launch Agent)")
            print("5. Workflow (Run Automation Chains)")
            print("6. Scoped Pentest (Interactive Mode)")
            print("7. Exit")
            
            choice = input("\nSelect an option [1-7]: ").strip()
            
            config = load_config()
            default_target = config.get('target', {}).get('ip', '127.0.0.1')
            
            if choice == '1': # Setup
                handle_setup(argparse.Namespace(dry_run=False))
                input("\nPress Enter to return to menu...")
                
            elif choice == '2': # Scan
                target = get_user_input("Target IP", default_target)
                handle_scan(argparse.Namespace(target=target, output=None, dry_run=False))
                input("\nPress Enter to return to menu...")
                
            elif choice == '3': # Classify
                input_file = get_user_input("Input file (.nessus/.json)")
                if not input_file:
                    print("Input file is required.")
                    input("\nPress Enter to return to menu...")
                    continue
                output_file = get_user_input("Output file (optional)")
                
                handle_classify(argparse.Namespace(
                    input_file=input_file,
                    output=output_file if output_file else None,
                    config=None,
                    init_config=False,
                    dry_run=False
                ))
                input("\nPress Enter to return to menu...")

            elif choice == '4': # Attack
                target = get_user_input("Target IP", default_target)
                input_file = get_user_input("Input vulnerabilities JSON (optional)")
                
                handle_attack(argparse.Namespace(
                    target=target,
                    input_file=input_file if input_file else None,
                    dry_run=False
                ))
                input("\nPress Enter to return to menu...")
                
            elif choice == '5': # Workflow
                wf_type = get_user_input("Workflow Type (ingest)", "ingest")
                
                if wf_type == 'ingest':
                    nessus = get_user_input("Nessus File Path")
                    if not nessus:
                        print("Nessus file required.")
                        input("\nPress Enter to return to menu...")
                        continue
                    handle_workflow(argparse.Namespace(
                        type='ingest',
                        target=None,
                        nessus_file=nessus,
                        dry_run=False
                    ))
                else:
                    print("Invalid workflow type. Only 'ingest' is supported.")
                
                input("\nPress Enter to return to menu...")
                
            elif choice == '6': # Scoped Pentest
                handle_scoped_pentest(argparse.Namespace(input_file=None, target=None))
                input("\nPress Enter to return to menu...")

            elif choice == '7':
                print("Exiting...")
                break
            else:
                print("Invalid selection.")
                input("\nPress Enter to return to menu...")

        except BackToMenu:
            print("\nReturning to main menu...")
            continue
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            input("\nPress Enter to continue...")

def main():
    # Check for interactive mode first
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(
        description="APFA - Intelligent Pentesting CLI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('--dry-run', action='store_true', help='Preview execution without running')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # --- Subcommands ---
    
    # Setup
    p_setup = subparsers.add_parser('setup', help='Interactive configuration')
    
    # Scan
    p_scan = subparsers.add_parser('scan', help='Run Nmap scanner')
    p_scan.add_argument('--target', help='Target IP address')
    p_scan.add_argument('--output', help='Output file path (optional)')
    
    # Classify
    p_cls = subparsers.add_parser('classify', help='Classify and enrich vulnerabilities')
    p_cls.add_argument('input_file', nargs='?', help='Input scan file (.nessus or .json)')
    p_cls.add_argument('--output', help='Output JSON file')
    p_cls.add_argument('--config', help='Filter configuration file')
    p_cls.add_argument('--init-config', action='store_true', help='Generate filter config template')
    
    # Attack
    p_atk = subparsers.add_parser('attack', help='Launch intelligent attack agent')
    p_atk.add_argument('--target', help='Target IP address')
    p_atk.add_argument('--input-file', help='Path to classified vulnerabilities JSON')
    
    # Workflow
    p_flow = subparsers.add_parser('workflow', help='Run predefined workflows')
    p_flow.add_argument('type', choices=['ingest'], help='Workflow type')
    p_flow.add_argument('--target', help='Target IP address')
    p_flow.add_argument('--nessus-file', help='Input Nessus file for ingest workflow')
    
    # Scoped Pentest
    p_scoped = subparsers.add_parser('scoped', help='Interactive Scoped Pentest')
    p_scoped.add_argument('--input-file', help='Input Nessus/JSON file')
    p_scoped.add_argument('--target', help='Target IP address')

    # Parse
    args = parser.parse_args()
    
    banner()
    
    if not args.command:
        parser.print_help()
        return
        
    # Dispatch
    if args.command == 'setup':
        handle_setup(args)
    elif args.command == 'scan':
        handle_scan(args)
    elif args.command == 'classify':
        handle_classify(args)
    elif args.command == 'attack':
        handle_attack(args)
    elif args.command == 'workflow':
        handle_workflow(args)
    elif args.command == 'scoped':
        handle_scoped_pentest(args)

if __name__ == "__main__":
    main()
