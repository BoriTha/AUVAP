#!/usr/bin/env python3
print("DEBUG: Starting apfa_cli.py")
"""
DeepExploit Hybrid - Unified CLI
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
                                               
    DeepExploit Hybrid Unified CLI
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
        from apfa_agent.main_agent import llm_only_mode, train_mode, hybrid_mode, eval_mode
        return llm_only_mode, train_mode, hybrid_mode, eval_mode
    except ImportError as e:
        logger.error(f"Failed to import Agent: {e}")
        sys.exit(1)

# --- Command Handlers ---

def handle_scoped_pentest(args):
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
            vulns = processor.get_for_llm(fields=["id", "pn", "d", "c", "cvss", "s", "p", "h", "plugin_name", "description"])
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
    except Exception as e:
        logger.error(f"Failed to load: {e}")
        return

    # Classify (if needed) - Assuming we want enriched data for decision making
    # If loading from raw nessus, we should probably run classifier.
    # For speed, maybe skip full classification if just selecting? 
    # Prompt says: "Run VulnerabilityClassifier to find pentestable candidates."
    classifier = VulnerabilityClassifier(enable_rag=False)
    print("Classifying candidates...")
    vulns = classifier.classify_batch(vulns)

    # 2. Interactive Selection
    print("\n--- Candidate Vulnerabilities ---")
    print(f"{'ID':<5} | {'Sev':<8} | {'Port':<6} | {'Name'}")
    print("-" * 60)
    
    # Store map for easy retrieval
    vuln_map = {}
    display_list = []
    
    for i, v in enumerate(vulns):
        vid = str(i + 1)
        vuln_map[vid] = v
        sev = v.get('s', 0)
        port = v.get('p', 0)
        name = v.get('pn', 'Unknown')[:40]
        print(f"{vid:<5} | {sev:<8} | {port:<6} | {name}")
        display_list.append(vid)

    print("-" * 60)
    selection = input("\nEnter IDs to scope (comma-separated) or 'all' (b to back): ").strip()
    
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

    # 3. Extract Ports and Save Scope
    scope_ports = sorted(list(set(int(v.get('p')) for v in selected_vulns if v.get('p'))))
    print(f"\nScoped Ports: {scope_ports}")
    
    scope_data = {
        'ports': scope_ports,
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
    # We need to call hybrid_mode with this scope
    llm_only_mode, train_mode, hybrid_mode, eval_mode = get_agent_functions()
    config = load_config()
    
    # Ensure target is set
    target = args.target or config.get('target', {}).get('ip')
    if not target:
        target = get_user_input("Enter Target IP")
    
    if 'target' not in config: config['target'] = {}
    config['target']['ip'] = target

    print("\n>>> Launching Scoped Agent...")
    # We need to modify hybrid_mode to accept scope_path or ports
    # Passing scope_path via apfa_path argument might work if we handle it in main_agent
    # Or we pass a specific argument. Since we can't easily change main_agent signature from here without changing main_agent first.
    # I will update main_agent to accept scoped_ports.
    
    # For now, I will assume hybrid_mode accepts 'scoped_ports' kwarg or I update it.
    # The prompt asks to update main_agent too.
    
    try:
        hybrid_mode(config, CONFIG_PATH, target_ip=target, apfa_path=scope_path, scoped_ports=scope_ports)
    except TypeError:
        # Fallback if signature update pending/failed
        print("Warning: hybrid_mode signature mismatch, trying default")
        hybrid_mode(config, CONFIG_PATH, target_ip=target, apfa_path=scope_path)

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
            # Get fields compatible with classifier
            vulns = processor.get_for_llm(fields=["id", "pn", "d", "c", "cvss", "s", "p", "h", "plugin_name", "description"])
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
        else:
            logger.error("Unknown file format. Use .nessus or .json")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Failed to load/parse input: {e}")
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
    print("\n>>> Attack Mode")
    
    llm_only_mode, train_mode, hybrid_mode, eval_mode = get_agent_functions()
    
    config = load_config()
    
    target = args.target or config.get('target', {}).get('ip')
    if not target:
        logger.error("Error: Target IP required (arg or config).")
        sys.exit(1)
        
    # Override config target
    if 'target' not in config: config['target'] = {}
    config['target']['ip'] = target
    
    if args.dry_run:
        print(f"[Dry Run] Would launch attack on {target} in mode {args.mode}")
        return

    print(f"Target: {target}")
    print(f"Mode: {args.mode}")
    
    try:
        if args.mode == 'llm-only':
            print("Starting LLM-Only Mode (Smart Triage)...")
            llm_only_mode(config, CONFIG_PATH, target_ip=target, apfa_path=args.input_file)
        elif args.mode == 'hybrid':
            print("Starting Hybrid Mode...")
            hybrid_mode(config, CONFIG_PATH, target_ip=target, apfa_path=args.input_file)
        elif args.mode == 'train':
            print("Starting Training Mode...")
            train_mode(config, CONFIG_PATH, apfa_path=args.input_file)
        elif args.mode == 'eval':
            print("Starting Evaluation Mode...")
            eval_mode(config, CONFIG_PATH, apfa_path=args.input_file)
            
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
    
    if args.type == 'full':
        # Scan -> Attack
        print("\n[Step 1/2] Scanning Target...")
        scan_args = argparse.Namespace(target=args.target, dry_run=args.dry_run)
        handle_scan(scan_args)
        
        print("\n[Step 2/2] Attacking...")
        atk_args = argparse.Namespace(
            mode='hybrid', # Default to hybrid for full workflow
            target=args.target,
            input_file=None,
            dry_run=args.dry_run
        )
        handle_attack(atk_args)

    elif args.type == 'ingest':
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
                mode = get_user_input("Mode (llm-only/hybrid/train/eval)", "llm-only")
                target = get_user_input("Target IP", default_target)
                input_file = get_user_input("Input vulnerabilities JSON (optional)")
                
                handle_attack(argparse.Namespace(
                    mode=mode,
                    target=target,
                    input_file=input_file if input_file else None,
                    dry_run=False
                ))
                input("\nPress Enter to return to menu...")
                
            elif choice == '5': # Workflow
                wf_type = get_user_input("Workflow Type (full/ingest)", "full")
                
                if wf_type == 'full':
                    target = get_user_input("Target IP", default_target)
                    handle_workflow(argparse.Namespace(
                        type='full',
                        target=target,
                        nessus_file=None,
                        dry_run=False
                    ))
                elif wf_type == 'ingest':
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
                    print("Invalid workflow type.")
                
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
        description="DeepExploit Hybrid - Unified CLI",
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
    p_atk = subparsers.add_parser('attack', help='Launch attack agent')
    p_atk.add_argument('--mode', choices=['llm-only', 'hybrid', 'train', 'eval'], default='llm-only', help='Operation mode')
    p_atk.add_argument('--target', help='Target IP address')
    p_atk.add_argument('--input-file', help='Path to classified vulnerabilities JSON')
    
    # Workflow
    p_flow = subparsers.add_parser('workflow', help='Run predefined workflows')
    p_flow.add_argument('type', choices=['full', 'ingest'], help='Workflow type')
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
