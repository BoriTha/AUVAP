"""
UI Components for APFA Redesigned CLI - No Emoji Version
Provides reusable, consistent interface components
"""

import os
import sys
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class Color(Enum):
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    
    # Background colors
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'
    BG_MAGENTA = '\033[105m'
    BG_CYAN = '\033[106m'
    BG_WHITE = '\033[107m'

@dataclass
class SelectionItem:
    """Represents a selectable item in the UI"""
    id: str
    title: str
    description: str = ""
    metadata: Optional[Dict[str, Any]] = None
    selected: bool = False
    selectable: bool = True

class UIComponent:
    """Base class for all UI components"""
    
    def __init__(self):
        self.width = 80
        self.height = 24
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
    def get_terminal_size(self) -> Tuple[int, int]:
        """Get current terminal dimensions"""
        try:
            size = os.get_terminal_size()
            return size.columns, size.lines
        except:
            return 80, 24
            
    def center_text(self, text: str, width: Optional[int] = None) -> str:
        """Center text within specified width"""
        if width is None:
            width = self.width
        return text.center(width)
        
    def draw_box(self, title: str = "", content: Optional[List[str]] = None, 
                 border_color: Color = Color.BLUE) -> str:
        """Draw a bordered box with title and content"""
        if content is None:
            content = []
            
        width = self.width - 4
        lines = []
        
        # Top border
        lines.append(f"{border_color.value}┌{'─' * width}┐{Color.RESET.value}")
        
        # Title
        if title:
            title_line = f"│ {Color.BOLD.value}{title}{Color.RESET.value}{' ' * (width - len(title) - 1)}│"
            lines.append(title_line)
            lines.append(f"├{'─' * width}┤")
        
        # Content
        for line in content:
            # Truncate long lines
            if len(line) > width - 2:
                line = line[:width - 5] + "..."
            lines.append(f"│ {line}{' ' * (width - len(line) - 2)}│")
        
        # Bottom border
        lines.append(f"{border_color.value}└{'─' * width}┘{Color.RESET.value}")
        
        return '\n'.join(lines)

class MenuSystem(UIComponent):
    """Enhanced menu system with keyboard navigation"""
    
    def __init__(self):
        super().__init__()
        self.current_selection = 0
        self.menu_items = []
        
    def show_banner(self, title: str = "APFA - Intelligent Pentesting CLI"):
        """Display the application banner"""
        self.clear_screen()
        
        banner = f"""
{Color.CYAN.value}╔════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {title}
║                                                                              ║
╚════════════════════════════════════════════════════════════════════════════╝{Color.RESET.value}

"""
        print(banner)
        
    def show_menu(self, title: str, options: List[Dict[str, Any]], 
                  show_back: bool = True) -> int:
        """Display an interactive menu and return selection"""
        self.menu_items = options
        self.current_selection = 0
        
        while True:
            self._display_menu(title, options, show_back)
            choice = self._get_menu_choice(show_back)
            
            if choice is not None:
                return choice
                
    def _display_menu(self, title: str, options: List[Dict[str, Any]], show_back: bool):
        """Display menu without clearing screen (fixes scrolling issue)"""
        # Move cursor to top and clear only what we need
        print(f"\033[H", end="")  # Move cursor to top
        print(f"\033[J", end="")  # Clear from cursor to end of screen
        
        self.show_banner(title)
        
        # Display menu options
        for i, option in enumerate(options):
            prefix = "->" if i == self.current_selection else "  "
            icon = option.get('icon', '•')
            title_text = option.get('title', f'Option {i+1}')
            desc = option.get('description', '')
            
            if i == self.current_selection:
                print(f"{prefix} {Color.BOLD.value}{Color.CYAN.value}{icon} {i+1}. {title_text}{Color.RESET.value}")
                if desc:
                    print(f"     {Color.DIM.value}{desc}{Color.RESET.value}")
            else:
                print(f"{prefix} {icon} {i+1}. {title_text}")
                if desc:
                    print(f"     {Color.DIM.value}{desc}{Color.RESET.value}")
        
        if show_back:
            back_text = "->" if self.current_selection == len(options) else "  "
            if self.current_selection == len(options):
                print(f"{back_text} {Color.BOLD.value}{Color.YELLOW.value}0. Back/Exit{Color.RESET.value}")
            else:
                print(f"{back_text} 0. Back/Exit")
            
        print(f"\n{Color.DIM.value}Use Arrow Keys to navigate, Enter to select, 0 to exit{Color.RESET.value}")
        
    def _get_menu_choice(self, show_back: bool) -> Optional[int]:
        """Get user choice with arrow key navigation"""
        try:
            import termios
            import tty
            
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                while True:
                    ch = sys.stdin.read(1)
                    
                    # Handle arrow keys
                    if ch == '\x1b':
                        ch += sys.stdin.read(2)
                        if ch == '\x1b[A':  # Up arrow
                            self.current_selection = max(0, self.current_selection - 1)
                            return None  # Redraw menu
                        elif ch == '\x1b[B':  # Down arrow
                            max_index = len(self.menu_items) if show_back else len(self.menu_items) - 1
                            self.current_selection = min(max_index, self.current_selection + 1)
                            return None  # Redraw menu
                    
                    if ch == '\r' or ch == '\n':  # Enter
                        if self.current_selection == len(self.menu_items) and show_back:
                            return -1
                        return self.current_selection
                    elif ch == '0' and show_back:
                        return -1
                    elif ch.isdigit() and 0 < int(ch) <= len(self.menu_items):
                        return int(ch) - 1
                    elif ch in ['q', 'Q']:
                        return -1
                        
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                
        except ImportError:
            # Fallback for Windows
            try:
                import msvcrt
                while True:
                    if msvcrt.kbhit():
                        ch = msvcrt.getch()
                        if ch == b'\r':
                            if self.current_selection == len(self.menu_items) and show_back:
                                return -1
                            return self.current_selection
                        elif ch == b'0' and show_back:
                            return -1
                        elif ch.isdigit() and 0 < int(ch.decode()) <= len(self.menu_items):
                            return int(ch.decode()) - 1
                        elif ch.decode() in ['q', 'Q']:
                            return -1
            except (ImportError, AttributeError):
                pass
            
            # Final fallback - simple input
            choice = input("Enter selection: ").strip()
            if choice == '0' and show_back:
                return -1
            elif choice.isdigit() and 0 < int(choice) <= len(self.menu_items):
                return int(choice) - 1
            elif choice.lower() in ['q', 'back', 'exit']:
                return -1
                
        except KeyboardInterrupt:
            return -1

class SelectionGrid(UIComponent):
    """Interactive grid for selecting vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.items = []
        self.selected_items = set()
        self.current_page = 0
        self.items_per_page = 10
        self.filters = {}
        self.menu_system = MenuSystem()
        
    def show_vulnerability_grid(self, vulnerabilities: List[Dict[str, Any]], 
                                title: str = "Smart Target Selection") -> List[Dict[str, Any]]:
        """Display interactive vulnerability selection grid"""
        self.items = vulnerabilities
        self.selected_items = set()
        self.current_page = 0
        
        while True:
            self._display_grid(vulnerabilities, title)
            choice = self._get_grid_choice()
            
            if choice == 'start':
                selected = [v for i, v in enumerate(vulnerabilities) if i in self.selected_items]
                if selected:
                    return selected
                else:
                    self._show_error("No targets selected!")
            elif choice == 'back':
                return []
            elif choice == 'filter':
                pass  # TODO: Implement filter functionality
            elif choice.startswith('select_'):
                self._toggle_selection(int(choice.split('_')[1]))
                
    def _display_grid(self, vulnerabilities: List[Dict[str, Any]], title: str):
        """Display vulnerability grid without clearing screen"""
        print(f"\033[H", end="")  # Move cursor to top
        print(f"\033[J", end="")  # Clear from cursor to end of screen
        self.menu_system.show_banner(title)
        
        # Show summary
        self._show_summary(vulnerabilities)
        
        # Show quick filters
        self._show_quick_filters()
        
        # Show vulnerability grid
        self._show_vulnerability_list()
        
        # Show controls
        self._show_grid_controls()
        
    def _show_summary(self, vulnerabilities: List[Dict[str, Any]]):
        """Display vulnerability summary statistics"""
        total = len(vulnerabilities)
        critical = len([v for v in vulnerabilities if v.get('s', 0) == 4])
        high = len([v for v in vulnerabilities if v.get('s', 0) == 3])
        medium = len([v for v in vulnerabilities if v.get('s', 0) == 2])
        low = len([v for v in vulnerabilities if v.get('s', 0) == 1])
        
        hosts = len(set(v.get('h', '') for v in vulnerabilities))
        ports = len(set(v.get('p', 0) for v in vulnerabilities))
        
        summary = f"""
{Color.BOLD}Summary:{Color.RESET}
   Total: {total} vulnerabilities | {hosts} hosts | {ports} ports
   Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}

"""
        print(summary)
        
    def _show_quick_filters(self):
        """Display quick filter options"""
        filters = """
Quick Filters: [C]ritical [H]igh [R]CE [W]eb Apps [A]ll

"""
        print(filters)
        
    def _show_vulnerability_list(self):
        """Display the vulnerability list with selection indicators"""
        start_idx = self.current_page * self.items_per_page
        end_idx = min(start_idx + self.items_per_page, len(self.items))
        
        # Header
        header = f"{'ID':<5} | {'Sel':<4} | {'Sev':<5} | {'CVSS':<6} | {'Port':<7} | {'Host':<16} | {'Service':<20} | {'CVE':<15}"
        separator = "-" * 80
        
        print(f"{Color.BOLD}{header}{Color.RESET}")
        print(f"{Color.DIM.value}{separator}{Color.RESET.value}")
        
        # Vulnerability rows
        for i in range(start_idx, end_idx):
            vuln = self.items[i]
            vuln_id = str(i + 1)
            selected = "X" if i in self.selected_items else " "
            
            # Severity with color
            severity_num = vuln.get('s', 0)
            severity_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
            severity = severity_map.get(severity_num, "Unknown")
            
            if severity_num == 4:
                severity = f"{Color.RED.value}{severity}{Color.RESET.value}"
            elif severity_num == 3:
                severity = f"{Color.YELLOW.value}{severity}{Color.RESET.value}"
            elif severity_num == 2:
                severity = f"{Color.YELLOW.value}{severity}{Color.RESET.value}"
            else:
                severity = f"{Color.GREEN.value}{severity}{Color.RESET.value}"
            
            cvss = f"{vuln.get('cvss', 0.0):.1f}"
            port = str(vuln.get('p', 0))
            host = vuln.get('h', 'Unknown')[:15]
            service = vuln.get('pn', 'Unknown')[:19]
            cve = vuln.get('c', 'N/A')[:14]
            
            # Highlight selected rows
            if i in self.selected_items:
                print(f"{Color.BOLD}{Color.CYAN.value}{vuln_id:<5} | [{selected}] | {severity:<13} | {cvss:<6} | {port:<7} | {host:<16} | {service:<20} | {cve:<15}{Color.RESET.value}")
            else:
                print(f"{vuln_id:<5} | [{selected}] | {severity:<13} | {cvss:<6} | {port:<7} | {host:<16} | {service:<20} | {cve:<15}")
        
        print(f"{Color.DIM.value}{separator}{Color.RESET.value}")
        
        # Pagination info
        total_pages = (len(self.items) + self.items_per_page - 1) // self.items_per_page
        page_info = f"Page {self.current_page + 1}/{total_pages} | Showing {start_idx + 1}-{end_idx} of {len(self.items)}"
        print(f"\n{Color.DIM.value}{page_info}{Color.RESET.value}")
        
    def _show_grid_controls(self) -> str:
        """Show control options and get user input"""
        controls = f"""
{Color.BOLD}Quick Actions:{Color.RESET}
   Selection:
     - Enter IDs (comma-separated): e.g., '1,3,5'
     - 'all': Select all displayed vulnerabilities
     - 'view <ID>': View full details (e.g., 'view 1')
   
   Filtering:
     - 'filter port <ports>': Include only ports (e.g., 'filter port 80,443,22')
     - 'filter cvss <min> <max>': Filter by CVSS range (e.g., 'filter cvss 7 10')
     - 'filter severity <levels>': critical,high,medium,low,info
     - 'filter cve': Only show vulnerabilities with CVE
   
   Navigation:
     - 'n': Next page | 'p': Previous page
     - 's': Start Assessment | 'b': Back to menu

{Color.DIM.value}Enter command: {Color.RESET.value}"""
        
        print(controls)
        
        try:
            choice = input("> ").strip().lower()
            
            if choice in ['s', 'start']:
                return 'start'
            elif choice in ['b', 'back', 'exit']:
                return 'back'
            elif choice in ['n', 'next']:
                self._next_page()
            elif choice in ['p', 'prev']:
                self._prev_page()
            elif choice == 'all':
                self._select_all()
            elif choice.startswith('view '):
                try:
                    view_id = choice.split()[1].strip()
                    if view_id.isdigit():
                        idx = int(view_id) - 1
                        if 0 <= idx < len(self.items):
                            self._view_details(idx)
                except (IndexError, ValueError):
                    pass
            elif choice.startswith('select_'):
                try:
                    idx = int(choice.split('_')[1])
                    if 0 <= idx < len(self.items):
                        self._toggle_selection(idx)
                except (IndexError, ValueError):
                    pass
                    
        except KeyboardInterrupt:
            return 'back'
            
        return 'continue'
        
    def _toggle_selection(self, index: int):
        """Toggle selection for a specific vulnerability"""
        if index in self.selected_items:
            self.selected_items.remove(index)
        else:
            self.selected_items.add(index)
            
    def _select_all(self):
        """Select all vulnerabilities"""
        self.selected_items = set(range(len(self.items)))
        
    def _next_page(self):
        """Go to next page"""
        total_pages = (len(self.items) + self.items_per_page - 1) // self.items_per_page
        if self.current_page < total_pages - 1:
            self.current_page += 1
            
    def _prev_page(self):
        """Go to previous page"""
        if self.current_page > 0:
            self.current_page -= 1
            
    def _view_details(self, index: int):
        """Show details for selected vulnerability"""
        if index >= len(self.items):
            return
            
        vuln = self.items[index]
        
        print(f"\n{Color.BOLD}Vulnerability Details - ID: {index + 1}{Color.RESET}")
        print("=" * 80)
        print(f"Name:        {vuln.get('pn', 'Unknown')}")
        print(f"CVE:         {vuln.get('c', 'N/A')}")
        print(f"CVSS Score:  {vuln.get('cvss', 0.0)}")
        
        severity_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        severity = severity_map.get(vuln.get('s', 0), 'Unknown')
        print(f"Severity:    {severity} ({vuln.get('s', 0)})")
        print(f"Port:        {vuln.get('p', 0)}")
        print(f"Host:        {vuln.get('h', 'Unknown')}")
        print(f"\nDescription:\n{vuln.get('d', 'No description available')}")
        
        if vuln.get('sol'):
            print(f"\nSolution:\n{vuln.get('sol')}")
            
        print("=" * 80)
        input("\nPress Enter to continue...")
        
    def _show_error(self, message: str):
        """Display error message"""
        print(f"{Color.RED.value}Error: {message}{Color.RESET.value}")
        time.sleep(2)

class ProgressBar(UIComponent):
    """Animated progress bar for long operations"""
    
    def __init__(self):
        super().__init__()
        self.width = 50
        
    def show_progress(self, current: int, total: int, message: str = ""):
        """Display progress bar"""
        if total == 0:
            percentage = 100
        else:
            percentage = (current / total) * 100
            
        filled = int(self.width * percentage / 100)
        bar = '█' * filled + '░' * (self.width - filled)
        
        print(f"\r{message} [{bar}] {percentage:.1f}%", end='', flush=True)
        
        if current >= total:
            print()  # New line when complete
            
    def show_indeterminate(self, message: str, duration: float = 0):
        """Show indeterminate progress animation"""
        import itertools
        spinner = itertools.cycle(['|', '/', '-', '\\'])
        
        start_time = time.time()
        
        try:
            while True:
                if duration > 0 and (time.time() - start_time) > duration:
                    break
                    
                print(f"\r{message} {next(spinner)}", end='', flush=True)
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print(f"\r{message} Complete", flush=True)

class ConfigPanel(UIComponent):
    """Interactive configuration panel"""
    
    def __init__(self):
        super().__init__()
        self.config_sections = {}
        self.menu_system = MenuSystem()
        
    def show_config_menu(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Display interactive configuration menu"""
        while True:
            print(f"\033[H", end="")  # Move cursor to top
            print(f"\033[J", end="")  # Clear from cursor to end of screen
            self.menu_system.show_banner("Settings & Configuration")
            
            # Show current config summary
            self._show_config_summary(config_data)
            
            # Show menu options
            options = [
                {'icon': '[NET]', 'title': 'Network Settings', 'description': 'Target IP, scan speed, timeouts'},
                {'icon': '[LLM]', 'title': 'LLM Configuration', 'description': 'Models, API keys, parameters'},
                {'icon': '[SAFE]', 'title': 'Safety & Limits', 'description': 'VM checks, allowed targets, time limits'},
                {'icon': '[FILE]', 'title': 'File Locations', 'description': 'Paths for scans, reports, logs'},
                {'icon': '[SAVE]', 'title': 'Save All Settings', 'description': 'Save current configuration'},
                {'icon': '[RESET]', 'title': 'Reset to Defaults', 'description': 'Restore default settings'},
                {'icon': '[BACK]', 'title': 'Back to Main Menu', 'description': 'Return to main menu'}
            ]
            
            choice = self.menu_system.show_menu("Configuration", options, show_back=False)
            
            if choice == 0:  # Network Settings
                config_data = self._configure_network(config_data)
            elif choice == 1:  # LLM Configuration
                config_data = self._configure_llm(config_data)
            elif choice == 2:  # Safety & Limits
                config_data = self._configure_safety(config_data)
            elif choice == 3:  # File Locations
                config_data = self._configure_files(config_data)
            elif choice == 4:  # Save
                self._save_config(config_data)
                print(f"{Color.GREEN.value}Configuration saved!{Color.RESET.value}")
                time.sleep(2)
            elif choice == 5:  # Reset
                if self._confirm_reset():
                    config_data = self._get_default_config()
                    print(f"{Color.YELLOW.value}Configuration reset to defaults{Color.RESET.value}")
                    time.sleep(2)
            elif choice == 6:  # Back
                break
                
        return config_data
        
    def _show_config_summary(self, config: Dict[str, Any]):
        """Display current configuration summary"""
        target = config.get('target', {}).get('ip', 'Not set')
        model = config.get('llm', {}).get('models', [{}])[0].get('name', 'Not set')
        vm_check = config.get('safety', {}).get('require_vm', False)
        
        summary = f"""
{Color.BOLD}Current Configuration Summary:{Color.RESET}
   Target: {target}
   LLM Model: {model}
   VM Check: {'Enabled' if vm_check else 'Disabled'}
   Reports: data/agent_results/

"""
        print(summary)
        
    def _configure_network(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure network settings"""
        print(f"\n{Color.BOLD}Network Settings{Color.RESET}")
        print("=" * 50)
        
        if 'target' not in config:
            config['target'] = {}
            
        current_target = config['target'].get('ip', '')
        new_target = input(f"Target IP [{current_target}]: ").strip()
        if new_target:
            config['target']['ip'] = new_target
            
        return config
        
    def _configure_llm(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure LLM settings"""
        print(f"\n{Color.BOLD}LLM Configuration{Color.RESET}")
        print("=" * 50)
        print("Configure LLM models and API keys")
        print("Note: Set environment variables for API keys (OPENROUTER_API_KEY, etc.)")
        input("\nPress Enter to continue...")
        return config
        
    def _configure_safety(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure safety settings"""
        print(f"\n{Color.BOLD}Safety & Limits{Color.RESET}")
        print("=" * 50)
        
        if 'safety' not in config:
            config['safety'] = {}
            
        current_vm = config['safety'].get('require_vm', True)
        vm_choice = input(f"Require VM check (y/n) [{ 'y' if current_vm else 'n' }]: ").strip().lower()
        if vm_choice in ['y', 'n']:
            config['safety']['require_vm'] = vm_choice == 'y'
            
        return config
        
    def _configure_files(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure file locations"""
        print(f"\n{Color.BOLD}File Locations{Color.RESET}")
        print("=" * 50)
        print("Current file locations:")
        print("  • Scan Results: data/scans/")
        print("  • Reports: data/agent_results/")
        print("  • Logs: logs/")
        input("\nPress Enter to continue...")
        return config
        
    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        import yaml
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                   '../../apfa_agent/config/agent_config.yaml')
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(config, f, sort_keys=False, default_flow_style=False)
        except Exception as e:
            print(f"{Color.RED.value}Error saving config: {e}{Color.RESET.value}")
            
    def _confirm_reset(self) -> bool:
        """Confirm configuration reset"""
        print(f"{Color.YELLOW.value}This will reset all settings to defaults{Color.RESET.value}")
        choice = input("Are you sure? (y/n): ").strip().lower()
        return choice == 'y'
        
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'target': {'ip': '127.0.0.1'},
            'scanning': {'mode': 'auto', 'sudo': False},
            'llm': {'models': []},
            'safety': {'require_vm': True},
            'execution': {'mode': 'safe'}
        }