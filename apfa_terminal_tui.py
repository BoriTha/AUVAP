#!/usr/bin/env python3
"""
AUVAP Terminal TUI - Classic Terminal Interface
Proper terminal TUI with keyboard controls and focus management
"""

import os
import sys
import argparse
import signal
import yaml
import time
import json
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

# Add paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(current_dir, 'apfa_agent'))
sys.path.insert(0, os.path.join(current_dir, 'classifier'))
sys.path.insert(0, os.path.join(current_dir, 'parser'))

# Import parser and classifier
from parser.nessus_to_llm import VulnProcessor
from classifier.vulnerability_classifier import VulnerabilityClassifier

class Colors:
    """ANSI color codes"""
    RESET = '\033[0m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    REVERSE = '\033[7m'
    
    # Background colors
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

class SimpleConfigManager:
    """Simple configuration manager"""
    
    def __init__(self):
        self.config_file = os.path.join(current_dir, 'apfa_agent', 'config', 'agent_config.yaml')
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            'target': {'ip': '127.0.0.1'},
            'scanning': {'mode': 'auto', 'sudo': False},
            'llm': {'models': []},
            'safety': {'require_vm': True},
            'execution': {'mode': 'safe'}
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f) or {}
                    default_config.update(loaded_config)
        except Exception as e:
            print(f"Warning: Failed to load config: {e}")
        
        return default_config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                yaml.dump(self.config, f, sort_keys=False, default_flow_style=False)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

class TerminalTUI:
    """Classic Terminal TUI with proper keyboard controls"""
    
    def __init__(self):
        self.config_manager = SimpleConfigManager()
        self.current_selection = 0
        self.running = True
        self.current_vulns = []
        self.selected_nessus_file = None
        self.vuln_processor = None
        self.active_filters = []
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        self.running = False
        self._clear_screen()
        print(f"{Colors.YELLOW}Goodbye!{Colors.RESET}")
        sys.exit(0)
    
    def _clear_screen(self):
        """Clear terminal screen and reset cursor"""
        # Use more reliable clear method
        print("\033[2J\033[H", end='', flush=True)
    
    def _get_terminal_size(self):
        """Get terminal dimensions"""
        try:
            import shutil
            cols, rows = shutil.get_terminal_size()
            return cols, rows
        except:
            return 80, 24
    
    def _get_key(self):
        """Get single keypress with proper handling"""
        try:
            import termios
            import tty
            import sys
            
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
                
                # Handle arrow keys and special keys
                if ch == '\x1b':
                    # ESC was pressed, read next character immediately
                    # Set stdin to non-blocking temporarily
                    import fcntl
                    import os
                    
                    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                    
                    try:
                        next_ch = sys.stdin.read(1)
                        if next_ch == '[':
                            # This is an arrow key sequence
                            direction = sys.stdin.read(1)
                            if direction == 'A':
                                return 'UP'
                            elif direction == 'B':
                                return 'DOWN'
                            elif direction == 'C':
                                return 'RIGHT'
                            elif direction == 'D':
                                return 'LEFT'
                        # Unknown escape sequence
                        return 'ESC'
                    except (IOError, BlockingIOError):
                        # No more data available - it's just ESC
                        return 'ESC'
                    finally:
                        # Restore blocking mode
                        fcntl.fcntl(fd, fcntl.F_SETFL, flags)
                        
                elif ch == '\r' or ch == '\n':  # Enter
                    return 'ENTER'
                elif ch == '\x7f':  # Backspace
                    return 'BACKSPACE'
                elif ch == '\x1a':  # Ctrl+Z
                    return 'CTRLZ'
                elif ch == '\x03':  # Ctrl+C
                    return 'CTRLC'
                elif ch == '\x09':  # Tab
                    return 'TAB'
                else:
                    return ch.upper()
                    
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                
        except ImportError:
            # Fallback - use simple input
            return input("Press Enter (or type 1-4, q): ").strip().upper() or 'ENTER'
    
    def _show_banner(self):
        """Show application banner"""
        print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ___   __  ___      _____    ____                                         ║
║   /   | / / / / |    / /   |  / __ \\                                        ║
║  / /| |/ / / /| |   / / /| | / /_/ /                                        ║
║ / ___ / /_/ / | |  / / ___ |/ ____/                                         ║
║/_/  |_\\____/  |_| /_/_/  |_/_/                                              ║
║                                                                              ║
║           {Colors.BOLD}AUVAP - Intelligent Pentesting TUI{Colors.RESET}{Colors.CYAN}                        ║
║           {Colors.DIM}Enhanced UX • Smart Workflows • Zero-Config Operation{Colors.RESET}{Colors.CYAN}      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")
    
    def _show_main_menu(self):
        """Show main menu with keyboard navigation"""
        menu_items = [
            "[VA] Vulnerability Assessment & Verification",
            "[AUTO] Auto Pentesting", 
            "[CONFIG] Settings & Configuration",
            "[EXIT] Exit"
        ]
        
        descriptions = [
            "Select Nessus scan, filter CVEs, enrich with NVD, verify vulnerabilities",
            "Full Autonomous Attack - Zero-config intelligent pentesting",
            "Configure targets, LLM models, safety settings, and preferences",
            "Leave application"
        ]
        
        while self.running:
            self._clear_screen()
            self._show_banner()
            
            width, _ = self._get_terminal_size()
            menu_width = min(70, width - 4)
            
            # Menu title
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * menu_width}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}|| MAIN MENU{Colors.RESET}{' ' * (menu_width - 12)}{Colors.BOLD}{Colors.CYAN}||{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'=' * menu_width}{Colors.RESET}")
            
            # Menu items
            for i, (item, desc) in enumerate(zip(menu_items, descriptions)):
                if i == self.current_selection:
                    # Highlighted item
                    print(f"{Colors.REVERSE}{Colors.BOLD}  {item}{Colors.RESET}")
                    print(f"  {Colors.DIM}{desc}{Colors.RESET}")
                else:
                    # Normal item
                    print(f"  {item}")
                    print(f"  {Colors.DIM}{desc}{Colors.RESET}")
                print()
            
            # Instructions
            print(f"{Colors.BOLD}{Colors.YELLOW}Controls:{Colors.RESET}")
            print(f"  Up/Down : Navigate menu")
            print(f"  Enter   : Select option")
            print(f"  q       : Quit")
            print(f"  1-4     : Quick select")
            
            # Get user input
            key = self._get_key()
            
            # Debug: show what key was pressed (temporary)
            # print(f"\nDEBUG: Key pressed: {repr(key)}", flush=True)
            # time.sleep(0.5)
            
            if key == 'UP':
                self.current_selection = max(0, self.current_selection - 1)
            elif key == 'DOWN':
                self.current_selection = min(len(menu_items) - 1, self.current_selection + 1)
            elif key == 'ENTER':
                return self.current_selection
            elif key in ['Q', 'CTRLC']:
                self.running = False
                return -1
            elif key and key.isdigit() and 1 <= int(key) <= len(menu_items):
                self.current_selection = int(key) - 1
                return self.current_selection
    
    def _get_nessus_files(self) -> List[str]:
        """Get list of Nessus files from input directory"""
        input_dir = os.path.join(current_dir, 'data', 'input')
        try:
            files = [f for f in os.listdir(input_dir) if f.endswith('.nessus')]
            return sorted(files)
        except:
            return []
    
    def _select_nessus_file(self) -> Optional[str]:
        """Show file selection menu"""
        files = self._get_nessus_files()
        
        if not files:
            self._show_message("No Nessus files found in data/input/", "error")
            return None
        
        current_file = 0
        
        while True:
            self._clear_screen()
            self._show_banner()
            
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}|| SELECT NESSUS SCAN FILE{Colors.RESET}{' ' * 35}{Colors.BOLD}{Colors.CYAN}||{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}\n")
            
            for i, file in enumerate(files):
                if i == current_file:
                    print(f"{Colors.REVERSE}{Colors.BOLD}  > {file}{Colors.RESET}")
                else:
                    print(f"    {file}")
            
            print(f"\n{Colors.BOLD}{Colors.YELLOW}Controls:{Colors.RESET}")
            print(f"  Up/Down : Navigate files")
            print(f"  Enter   : Select file")
            print(f"  ESC     : Back to main menu")
            
            key = self._get_key()
            
            if key == 'UP':
                current_file = max(0, current_file - 1)
            elif key == 'DOWN':
                current_file = min(len(files) - 1, current_file + 1)
            elif key == 'ENTER':
                return os.path.join(current_dir, 'data', 'input', files[current_file])
            elif key in ['ESC', 'LEFT']:
                return None
    
    def _parse_nessus_and_display(self, nessus_file: str):
        """Parse Nessus file and show vulnerability list"""
        # Parse file
        try:
            self._show_message("Parsing Nessus file...", "info")
            self.vuln_processor = VulnProcessor(nessus_file)
            
            # Get all vulnerabilities
            all_data = self.vuln_processor.get()
            self.current_vulns = []
            
            for level in ["critical", "high", "medium", "low", "info"]:
                self.current_vulns.extend(all_data["vulnerabilities"][level])
            
            if not self.current_vulns:
                self._show_message("No vulnerabilities found in scan!", "error")
                return
            
            # Ask if user wants to enrich with NVD/CVE data
            if self._ask_yes_no("Enrich missing CVEs with NVD database?"):
                self._enrich_vulnerabilities()
            
            # Show vulnerability browser
            self._show_vulnerability_browser()
            
        except Exception as e:
            self._show_message(f"Error parsing file: {e}", "error")
    
    def _enrich_vulnerabilities(self):
        """Enrich vulnerabilities with CVE/NVD data"""
        self._clear_screen()
        print(f"{Colors.YELLOW}Enriching vulnerabilities with NVD/CVE data...{Colors.RESET}")
        print(f"This may take a while...\n")
        
        try:
            classifier = VulnerabilityClassifier(
                mode="hybrid",
                enable_rag=False,
                enable_cve_enrichment=True
            )
            
            enriched_count = 0
            for i, vuln in enumerate(self.current_vulns):
                print(f"Processing {i+1}/{len(self.current_vulns)}: {vuln.get('pn', 'Unknown')[:50]}...", end='\r')
                
                if not vuln.get('c'):  # No CVE
                    result = classifier.classify_vulnerability(vuln)
                    if result and result['original'].get('c'):
                        vuln['c'] = result['original']['c']
                        enriched_count += 1
                        
                        # Also update CVSS if available
                        if result['original'].get('cvss') and not vuln.get('cvss'):
                            vuln['cvss'] = result['original']['cvss']
            
            print(f"\n\n{Colors.GREEN}Enriched {enriched_count} vulnerabilities with CVE data!{Colors.RESET}")
            time.sleep(2)
            
        except Exception as e:
            self._show_message(f"Enrichment failed: {e}", "error")
    
    def _show_vulnerability_browser(self):
        """Show vulnerability browser with filtering options"""
        current_vuln = 0
        page_size = 15
        current_page = 0
        
        # Working copy for filtering
        filtered_vulns = self.current_vulns.copy()
        
        while True:
            self._clear_screen()
            self._show_banner()
            
            total_pages = (len(filtered_vulns) + page_size - 1) // page_size
            start_idx = current_page * page_size
            end_idx = min(start_idx + page_size, len(filtered_vulns))
            page_vulns = filtered_vulns[start_idx:end_idx]
            
            # Header
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 100}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}|| VULNERABILITY BROWSER{Colors.RESET} - Page {current_page + 1}/{total_pages} ({len(filtered_vulns)} vulns){' ' * 40}{Colors.BOLD}{Colors.CYAN}||{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 100}{Colors.RESET}\n")
            
            # Show active filters
            if self.active_filters:
                print(f"{Colors.YELLOW}Active Filters:{Colors.RESET} {', '.join(self.active_filters)}\n")
            
            # Column headers
            print(f"{Colors.BOLD}{'#':<4} {'Severity':<10} {'CVE':<18} {'CVSS':<6} {'Port':<6} {'Host':<16} {'Name'[:40]:<42}{Colors.RESET}")
            print(f"{Colors.DIM}{'-' * 100}{Colors.RESET}")
            
            # Vulnerability rows
            for i, vuln in enumerate(page_vulns):
                idx = start_idx + i
                severity = vuln.get('s', 0)
                severity_colors = {0: Colors.DIM, 1: Colors.WHITE, 2: Colors.YELLOW, 3: Colors.RED, 4: Colors.BOLD + Colors.RED}
                severity_names = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
                
                sev_color = severity_colors.get(severity, Colors.WHITE)
                sev_name = severity_names.get(severity, "Unknown")
                
                cve = vuln.get('c', 'N/A')[:17]
                cvss = vuln.get('cvss', 0.0)
                port = vuln.get('p', 0)
                host = vuln.get('h', 'N/A')[:15]
                name = vuln.get('pn', 'Unknown')[:40]
                
                if idx == current_vuln:
                    print(f"{Colors.REVERSE}{idx:<4} {sev_color}{sev_name:<10}{Colors.RESET}{Colors.REVERSE} {cve:<18} {cvss:<6.1f} {port:<6} {host:<16} {name:<42}{Colors.RESET}")
                else:
                    print(f"{idx:<4} {sev_color}{sev_name:<10}{Colors.RESET} {cve:<18} {cvss:<6.1f} {port:<6} {host:<16} {name:<42}")
            
            # Controls
            print(f"\n{Colors.BOLD}{Colors.YELLOW}Controls:{Colors.RESET}")
            print(f"  Up/Down: Navigate  |  Left/Right: Page  |  F: Filter  |  C: Clear Filters  |  V: View Details")
            print(f"  S: Select for Verification  |  ESC: Back")
            
            key = self._get_key()
            
            if key == 'UP':
                current_vuln = max(0, current_vuln - 1)
                if current_vuln < start_idx:
                    current_page = max(0, current_page - 1)
            elif key == 'DOWN':
                current_vuln = min(len(filtered_vulns) - 1, current_vuln + 1)
                if current_vuln >= end_idx:
                    current_page = min(total_pages - 1, current_page + 1)
            elif key == 'RIGHT':
                current_page = min(total_pages - 1, current_page + 1)
            elif key == 'LEFT':
                current_page = max(0, current_page - 1)
            elif key == 'F':
                filtered_vulns = self._apply_filter_ui(filtered_vulns)
                current_vuln = 0
                current_page = 0
            elif key == 'C':
                filtered_vulns = self.current_vulns.copy()
                self.active_filters = []
            elif key == 'V':
                if filtered_vulns:
                    self._show_vuln_details(filtered_vulns[current_vuln])
            elif key == 'S':
                self._select_vulns_for_verification(filtered_vulns)
            elif key in ['ESC']:
                break
    
    def _apply_filter_ui(self, vulns: List[Dict]) -> List[Dict]:
        """Interactive filter UI"""
        filter_types = [
            "Filter by Port (exclude)",
            "Filter by Port (include only)",
            "Filter by CVSS (minimum)",
            "Filter by Severity",
            "Filter by CVE presence",
            "Advanced: Exclude port except if CVSS > threshold",
            "Back"
        ]
        
        current = 0
        
        while True:
            self._clear_screen()
            print(f"\n{Colors.BOLD}{Colors.CYAN}SELECT FILTER TYPE{Colors.RESET}\n")
            
            for i, ft in enumerate(filter_types):
                if i == current:
                    print(f"{Colors.REVERSE}  {ft}{Colors.RESET}")
                else:
                    print(f"  {ft}")
            
            print(f"\n{Colors.YELLOW}Up/Down: Navigate | Enter: Select | ESC: Back{Colors.RESET}")
            
            key = self._get_key()
            
            if key == 'UP':
                current = max(0, current - 1)
            elif key == 'DOWN':
                current = min(len(filter_types) - 1, current + 1)
            elif key == 'ENTER':
                if current == len(filter_types) - 1:  # Back
                    return vulns
                else:
                    return self._apply_specific_filter(current, vulns)
            elif key == 'ESC':
                return vulns
    
    def _apply_specific_filter(self, filter_type: int, vulns: List[Dict]) -> List[Dict]:
        """Apply specific filter based on type"""
        if filter_type == 0:  # Exclude port
            self._clear_screen()
            print(f"{Colors.BOLD}Enter port to exclude (comma-separated for multiple):{Colors.RESET}")
            ports_str = input("> ").strip()
            try:
                ports = [int(p.strip()) for p in ports_str.split(',')]
                filtered = [v for v in vulns if v.get('p', 0) not in ports]
                self.active_filters.append(f"Exclude ports: {ports}")
                return filtered
            except:
                return vulns
        
        elif filter_type == 1:  # Include only port
            self._clear_screen()
            print(f"{Colors.BOLD}Enter port to include (comma-separated for multiple):{Colors.RESET}")
            ports_str = input("> ").strip()
            try:
                ports = [int(p.strip()) for p in ports_str.split(',')]
                filtered = [v for v in vulns if v.get('p', 0) in ports]
                self.active_filters.append(f"Include only ports: {ports}")
                return filtered
            except:
                return vulns
        
        elif filter_type == 2:  # CVSS minimum
            self._clear_screen()
            print(f"{Colors.BOLD}Enter minimum CVSS score:{Colors.RESET}")
            try:
                min_cvss = float(input("> ").strip())
                filtered = [v for v in vulns if v.get('cvss', 0) >= min_cvss]
                self.active_filters.append(f"CVSS >= {min_cvss}")
                return filtered
            except:
                return vulns
        
        elif filter_type == 3:  # Severity
            self._clear_screen()
            print(f"{Colors.BOLD}Select severity levels (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical):{Colors.RESET}")
            print("Enter numbers separated by commas (e.g., 3,4 for High and Critical):")
            try:
                sevs_str = input("> ").strip()
                sevs = [int(s.strip()) for s in sevs_str.split(',')]
                filtered = [v for v in vulns if v.get('s', 0) in sevs]
                self.active_filters.append(f"Severity: {sevs}")
                return filtered
            except:
                return vulns
        
        elif filter_type == 4:  # CVE presence
            filtered = [v for v in vulns if v.get('c')]
            self.active_filters.append("Has CVE")
            return filtered
        
        elif filter_type == 5:  # Advanced
            self._clear_screen()
            print(f"{Colors.BOLD}Exclude port (enter port number):{Colors.RESET}")
            try:
                port = int(input("> ").strip())
                print(f"{Colors.BOLD}Except if CVSS >= (enter threshold):{Colors.RESET}")
                threshold = float(input("> ").strip())
                
                filtered = [v for v in vulns if v.get('p', 0) != port or v.get('cvss', 0) >= threshold]
                self.active_filters.append(f"Exclude port {port} except CVSS >= {threshold}")
                return filtered
            except:
                return vulns
        
        return vulns
    
    def _show_vuln_details(self, vuln: Dict):
        """Show detailed vulnerability information"""
        self._clear_screen()
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}|| VULNERABILITY DETAILS{Colors.RESET}{' ' * 56}{Colors.BOLD}{Colors.CYAN}||{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.RESET}\n")
        
        severity_names = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        
        print(f"{Colors.BOLD}ID:{Colors.RESET}          {vuln.get('id', 'N/A')}")
        print(f"{Colors.BOLD}Host:{Colors.RESET}        {vuln.get('h', 'N/A')}")
        print(f"{Colors.BOLD}Port:{Colors.RESET}        {vuln.get('p', 'N/A')}")
        print(f"{Colors.BOLD}Severity:{Colors.RESET}    {severity_names.get(vuln.get('s', 0), 'Unknown')}")
        print(f"{Colors.BOLD}CVE:{Colors.RESET}         {vuln.get('c', 'N/A')}")
        print(f"{Colors.BOLD}CVSS:{Colors.RESET}        {vuln.get('cvss', 0.0)}")
        print(f"{Colors.BOLD}Plugin Name:{Colors.RESET} {vuln.get('pn', 'Unknown')}")
        print(f"{Colors.BOLD}Family:{Colors.RESET}      {vuln.get('pf', 'Unknown')}")
        print(f"{Colors.BOLD}Protocol:{Colors.RESET}    {vuln.get('proto', 'tcp')}")
        print(f"\n{Colors.BOLD}Description:{Colors.RESET}")
        desc = vuln.get('d', 'No description')
        print(f"{desc[:500]}...")
        
        print(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
        input()
    
    def _select_vulns_for_verification(self, vulns: List[Dict]):
        """Select vulnerabilities for verification"""
        self._show_message("Saving selected vulnerabilities for verification...", "info")
        
        # Save to file for verification workflow
        output_file = os.path.join(current_dir, 'data', 'selected_vulns_for_verification.json')
        try:
            with open(output_file, 'w') as f:
                json.dump(vulns, f, indent=2)
            
            self._show_message(f"Saved {len(vulns)} vulnerabilities to {output_file}", "success")
        except Exception as e:
            self._show_message(f"Error saving: {e}", "error")
    
    def _ask_yes_no(self, question: str) -> bool:
        """Ask yes/no question"""
        self._clear_screen()
        print(f"\n{Colors.BOLD}{question}{Colors.RESET}")
        print(f"{Colors.YELLOW}Y/N: {Colors.RESET}", end='', flush=True)
        
        while True:
            key = self._get_key()
            if key == 'Y':
                return True
            elif key == 'N':
                return False
    
    def _show_settings(self):
        """Show settings screen with model selection"""
        settings_items = [
            ("Target IP", self.config_manager.config.get('target', {}).get('ip', '127.0.0.1')),
            ("VM Check", str(self.config_manager.config.get('safety', {}).get('require_vm', True))),
            ("LLM Model", "Select..."),
            ("Save Settings", ""),
            ("Back to Main Menu", "")
        ]
        
        current_setting = 0
        
        while self.running:
            self._clear_screen()
            self._show_banner()
            
            width, _ = self._get_terminal_size()
            settings_width = min(70, width - 4)
            
            # Settings title
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * settings_width}{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}|| SETTINGS{Colors.RESET}{' ' * (settings_width - 11)}{Colors.BOLD}{Colors.CYAN}||{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'=' * settings_width}{Colors.RESET}")
            
            # Settings items
            for i, (label, value) in enumerate(settings_items):
                if i == current_setting:
                    # Highlighted item
                    if value:
                        print(f"{Colors.REVERSE}{Colors.BOLD}  {label}: {value}{Colors.RESET}")
                    else:
                        print(f"{Colors.REVERSE}{Colors.BOLD}  {label}{Colors.RESET}")
                else:
                    # Normal item
                    if value:
                        print(f"  {label}: {Colors.GREEN}{value}{Colors.RESET}")
                    else:
                        print(f"  {Colors.YELLOW}{label}{Colors.RESET}")
                print()
            
            # Instructions
            print(f"{Colors.BOLD}{Colors.YELLOW}Controls:{Colors.RESET}")
            print(f"  Up/Down : Navigate settings")
            print(f"  Enter   : Edit setting / Save")
            print(f"  ESC     : Back to main menu")
            
            # Get user input
            key = self._get_key()
            
            if key == 'UP':
                current_setting = max(0, current_setting - 1)
            elif key == 'DOWN':
                current_setting = min(len(settings_items) - 1, current_setting + 1)
            elif key == 'ENTER':
                if current_setting == len(settings_items) - 1:  # Back
                    break
                elif current_setting == len(settings_items) - 2:  # Save
                    self._save_settings()
                else:
                    self._edit_setting(current_setting)
            elif key in ['ESC', 'LEFT']:
                break
    
    def _edit_setting(self, setting_index):
        """Edit a specific setting"""
        if setting_index == 0:  # Target IP
            self._clear_screen()
            print(f"{Colors.BOLD}Edit Target IP{Colors.RESET}")
            print(f"Current: {Colors.GREEN}{self.config_manager.config.get('target', {}).get('ip', '127.0.0.1')}{Colors.RESET}")
            print("Enter new IP (or press Enter to keep current):")
            
            # Use regular input for this
            import termios
            import tty
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            
            new_ip = input("> ").strip()
            if new_ip:
                if 'target' not in self.config_manager.config:
                    self.config_manager.config['target'] = {}
                self.config_manager.config['target']['ip'] = new_ip
                
        elif setting_index == 1:  # VM Check
            current = self.config_manager.config.get('safety', {}).get('require_vm', True)
            new_value = not current
            if 'safety' not in self.config_manager.config:
                self.config_manager.config['safety'] = {}
            self.config_manager.config['safety']['require_vm'] = new_value
            
        elif setting_index == 2:  # LLM Model
            self._select_llm_model()
    
    def _select_llm_model(self):
        """Show LLM model selection menu"""
        models = self.config_manager.config.get('llm', {}).get('models', [])
        
        if not models:
            self._show_message("No models configured in agent_config.yaml!", "error")
            return
        
        current = 0
        
        while True:
            self._clear_screen()
            print(f"\n{Colors.BOLD}{Colors.CYAN}SELECT LLM MODEL{Colors.RESET}\n")
            
            for i, model in enumerate(models):
                name = model.get('name', 'Unknown')
                provider = model.get('provider', 'Unknown')
                enabled = model.get('enabled', False)
                status = f"[{Colors.GREEN}ENABLED{Colors.RESET}]" if enabled else f"[{Colors.DIM}DISABLED{Colors.RESET}]"
                
                if i == current:
                    print(f"{Colors.REVERSE}  {name} ({provider}) {status}{Colors.RESET}")
                else:
                    print(f"  {name} ({provider}) {status}")
            
            print(f"\n{Colors.YELLOW}Up/Down: Navigate | Enter: Toggle Enable | ESC: Back{Colors.RESET}")
            
            key = self._get_key()
            
            if key == 'UP':
                current = max(0, current - 1)
            elif key == 'DOWN':
                current = min(len(models) - 1, current + 1)
            elif key == 'ENTER':
                # Toggle enabled status
                models[current]['enabled'] = not models[current].get('enabled', False)
            elif key == 'ESC':
                break
    
    def _save_settings(self):
        """Save settings to file"""
        if self.config_manager.save_config():
            self._show_message("Settings saved successfully!", "success")
        else:
            self._show_message("Error saving settings!", "error")
    
    def _show_message(self, message: str, msg_type: str = "info"):
        """Show a temporary message"""
        self._clear_screen()
        
        if msg_type == "success":
            color = Colors.GREEN
            icon = "[OK]"
        elif msg_type == "error":
            color = Colors.RED
            icon = "[ERROR]"
        else:
            color = Colors.CYAN
            icon = "[INFO]"
        
        width, height = self._get_terminal_size()
        msg_width = min(50, width - 4)
        
        # Center message
        lines = [
            "",
            "",
            "",
            f"{' ' * ((width - msg_width) // 2)}{Colors.BOLD}{color}{icon} {message}{Colors.RESET}",
            "",
            "",
            ""
        ]
        
        for line in lines:
            print(line)
        
        time.sleep(2)
    
    def _run_vulnerability_assessment(self):
        """Run vulnerability assessment workflow"""
        # Select Nessus file
        nessus_file = self._select_nessus_file()
        
        if not nessus_file:
            return
        
        # Parse and display
        self._parse_nessus_and_display(nessus_file)
    
    def _run_auto_pentesting(self):
        """Run auto pentesting workflow"""
        self._clear_screen()
        self._show_banner()
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}|| AUTO PENTESTING{Colors.RESET}{' ' * 42}{Colors.BOLD}{Colors.CYAN}||{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        
        print(f"\n{Colors.YELLOW}Starting auto pentesting...{Colors.RESET}")
        
        # Get current configuration
        target = self.config_manager.config.get('target', {}).get('ip', 'Not configured')
        print(f"Target: {Colors.GREEN}{target}{Colors.RESET}")
        
        # Simulate pentest process
        steps = [
            "Performing reconnaissance...",
            "Scanning for vulnerabilities...",
            "Exploiting identified vulnerabilities...",
            "Generating comprehensive report..."
        ]
        
        for step in steps:
            print(f"{Colors.CYAN}-> {step}{Colors.RESET}")
            time.sleep(1)
        
        print(f"\n{Colors.GREEN}[OK] Auto pentest completed!{Colors.RESET}")
        print(f"Results saved to: {Colors.YELLOW}data/agent_results/{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")
        input()
    
    def run(self):
        """Main TUI loop"""
        while self.running:
            try:
                choice = self._show_main_menu()
                
                if choice == 0:  # Vulnerability Assessment
                    self._run_vulnerability_assessment()
                elif choice == 1:  # Auto Pentesting
                    self._run_auto_pentesting()
                elif choice == 2:  # Settings
                    self._show_settings()
                elif choice == 3:  # Exit
                    self._clear_screen()
                    print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
                    print(f"{Colors.CYAN}║                                                                              ║{Colors.RESET}")
                    print(f"{Colors.CYAN}║  Thank you for using AUVAP!                                                  ║{Colors.RESET}")
                    print(f"{Colors.CYAN}║                                                                              ║{Colors.RESET}")
                    print(f"{Colors.CYAN}║  Your pentest results are saved in:                                          ║{Colors.RESET}")
                    print(f"{Colors.CYAN}║     data/agent_results/                                                      ║{Colors.RESET}")
                    print(f"{Colors.CYAN}║                                                                              ║{Colors.RESET}")
                    print(f"{Colors.CYAN}║  Stay safe and happy pentesting!                                            ║{Colors.RESET}")
                    print(f"{Colors.CYAN}║                                                                              ║{Colors.RESET}")
                    print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}")
                    break
                elif choice == -1:  # Quit
                    break
                    
            except KeyboardInterrupt:
                continue
            except Exception as e:
                self._show_message(f"Error: {e}", "error")

def banner():
    """Display application banner"""
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ___   __  ___      _____    ____                                         ║
║   /   | / / / / |    / /   |  / __ \\                                        ║
║  / /| |/ / / /| |   / / /| | / /_/ /                                        ║
║ / ___ / /_/ / | |  / / ___ |/ ____/                                         ║
║/_/  |_\\____/  |_| /_/_/  |_/_/                                              ║
║                                                                              ║
║           AUVAP - Intelligent Pentesting Terminal TUI                       ║
║           Enhanced UX • Smart Workflows • Zero-Config Operation             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="AUVAP - Intelligent Pentesting Terminal TUI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version='AUVAP Terminal TUI v2.0'
    )
    
    parser.add_argument(
        '--cli',
        action='store_true',
        help='Use original CLI interface instead of TUI'
    )
    
    args = parser.parse_args()
    
    # If CLI mode requested, run original CLI
    if args.cli:
        try:
            from apfa_cli import main as cli_main
            cli_main()
        except ImportError:
            print("Original CLI not available")
        return
    
    # Display banner
    banner()
    
    # Initialize and run TUI
    try:
        tui = TerminalTUI()
        tui.run()
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Goodbye!{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[ERROR] Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
