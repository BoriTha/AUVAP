#!/usr/bin/env python3
"""
AUVAP CLI
Intelligent Pentesting CLI with Enhanced UX
"""

import os
import sys
import argparse
import signal
from typing import Optional

# Add paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(current_dir, 'apfa_agent'))
sys.path.insert(0, os.path.join(current_dir, 'classifier'))
sys.path.insert(0, os.path.join(current_dir, 'parser'))

try:
    from ui.components import MenuSystem, Color
    from ui.config_manager import ConfigManager
    from ui.workflows.vulnerability_assessment import VulnerabilityAssessment
    from ui.workflows.auto_pentesting import AutoPentesting
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure you're running from the project root directory")
    sys.exit(1)

class APFARedesignedCLI:
    """Redesigned APFA CLI with enhanced UX"""
    
    def __init__(self):
        self.menu_system = MenuSystem()
        self.config_manager = ConfigManager()
        self.vulnerability_assessment = VulnerabilityAssessment()
        self.auto_pentesting = AutoPentesting()
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n\n{Color.YELLOW.value}👋 Goodbye!{Color.RESET.value}")
        sys.exit(0)
        
    def run_interactive_mode(self):
        """Run the main interactive menu"""
        while True:
            try:
                choice = self._show_main_menu()
                
                if choice == 0:  # Vulnerability Assessment
                    self._run_vulnerability_assessment()
                elif choice == 1:  # Auto Pentesting
                    self._run_auto_pentesting()
                elif choice == 2:  # Settings
                    self._run_settings()
                elif choice == 3:  # Exit
                    self._exit_application()
                    break
                    
            except KeyboardInterrupt:
                continue
            except Exception as e:
                print(f"{Color.RED.value}❌ Error: {e}{Color.RESET.value}")
                input("Press Enter to continue...")
                
    def _show_main_menu(self) -> int:
        """Display the main menu"""
        options = [
            {
                'icon': '[VA]',
                'title': 'Vulnerability Assessment',
                'description': 'Smart Scan & Target Selection - Enhanced scoped pentesting with visual interface'
            },
            {
                'icon': '[AUTO]',
                'title': 'Auto Pentesting',
                'description': 'Full Autonomous Attack - Zero-config intelligent pentesting'
            },
            {
                'icon': '[SET]',
                'title': 'Settings & Configuration',
                'description': 'Configure targets, LLM models, safety settings, and preferences'
            },
            {
                'icon': '[EXIT]',
                'title': 'Exit',
                'description': 'Leave application'
            }
        ]
        
        return self.menu_system.show_menu(
            "🎯 AUVAP - Intelligent Pentesting CLI",
            options,
            show_back=False
        )
        
    def _run_vulnerability_assessment(self):
        """Run vulnerability assessment workflow"""
        print(f"{Color.CYAN.value}🚀 Launching Vulnerability Assessment...{Color.RESET.value}")
        
        # Pass current configuration to the workflow
        success = self.vulnerability_assessment.run_assessment(
            self.config_manager.config
        )
        
        if success:
            print(f"{Color.GREEN.value}✅ Vulnerability assessment completed successfully!{Color.RESET.value}")
            print(f"📁 Results saved to: data/agent_results/")
        else:
            print(f"{Color.YELLOW.value}⚠️  Vulnerability assessment cancelled or failed{Color.RESET.value}")
            
        input("\nPress Enter to return to main menu...")
        
    def _run_auto_pentesting(self):
        """Run auto pentesting workflow"""
        print(f"{Color.CYAN.value}🚀 Launching Auto Pentesting...{Color.RESET.value}")
        
        # Pass current configuration to the workflow
        success = self.auto_pentesting.run_auto_pentest(
            self.config_manager.config
        )
        
        if success:
            print(f"{Color.GREEN.value}✅ Auto pentest completed successfully!{Color.RESET.value}")
            print(f"📁 Results saved to: data/agent_results/")
        else:
            print(f"{Color.YELLOW.value}⚠️  Auto pentest cancelled or failed{Color.RESET.value}")
            
        input("\nPress Enter to return to main menu...")
        
    def _run_settings(self):
        """Run settings configuration"""
        print(f"{Color.CYAN.value}⚙️  Opening Settings...{Color.RESET.value}")
        
        # Update configuration from user interaction
        self.config_manager.config = self.config_manager.show_config_menu()
        
        # Save the updated configuration
        self.config_manager.save_config()
        
    def _exit_application(self):
        """Exit the application gracefully"""
        self.menu_system.clear_screen()
        print(f"""
{Color.CYAN.value}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  Thank you for using AUVAP!                                                    ║
║                                                                              ║
║  Your pentest results are saved in:                                           ║
║     data/agent_results/                                                         ║
║                                                                              ║
║  Need to run another pentest?                                                 ║
║     ./apfa_cli.py                                                   ║
║                                                                              ║
║  Need help?                                                                    ║
║     Check README.md and documentation                                            ║
║                                                                              ║
╚════════════════════════════════════════════════════════════════════════════╝
{Color.RESET.value}
""")
        
        # Save any unsaved configuration
        self.config_manager.save_config()
        
        print(f"{Color.GREEN.value}Stay safe and happy pentesting! 🔐{Color.RESET.value}")

def banner():
    """Display application banner"""
    print(f"""
{Color.CYAN.value}    ___    ____  _______  __   ________    ____
   /   |  / __ \/ ____/ |/ /  / ____/ /   /  _/
  / /| | / /_/ / /_  / /|_/  / /   / /    / /  
 / ___ |/ ____/ __/ / /  /  / /___/ /____/ /   
/_/  |_/_/   /_/   /_/  /_/  \____/_____/___/                                                
{Color.BOLD}    AUVAP - Intelligent Pentesting CLI (Redesigned){Color.RESET.value}
{Color.DIM.value}    Enhanced UX • Smart Workflows • Zero-Config Operation{Color.RESET.value}
""")

def main():
    """Main entry point"""
    # Check for command line arguments
    parser = argparse.ArgumentParser(
        description="AUVAP - Intelligent Pentesting CLI (Redesigned)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version='AUVAP Redesigned v2.0'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--quick-scan',
        metavar='TARGET',
        help='Quick scan against target (non-interactive)'
    )
    
    parser.add_argument(
        '--auto-pentest',
        metavar='TARGET',
        help='Auto pentest against target (non-interactive)'
    )
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Initialize CLI
    try:
        cli = APFARedesignedCLI()
        
        # Handle command line modes
        if args.quick_scan:
            print(f"{Color.CYAN.value}🔍 Quick Scan Mode: {args.quick_scan}{Color.RESET.value}")
            # TODO: Implement quick scan mode
            print("Quick scan mode coming soon!")
            return
            
        elif args.auto_pentest:
            print(f"{Color.CYAN.value}🤖 Auto Pentest Mode: {args.auto_pentest}{Color.RESET.value}")
            # TODO: Implement auto pentest mode
            print("Auto pentest mode coming soon!")
            return
            
        else:
            # Run interactive mode
            cli.run_interactive_mode()
            
    except KeyboardInterrupt:
        print(f"\n\n{Color.YELLOW.value}👋 Goodbye!{Color.RESET.value}")
    except Exception as e:
        print(f"{Color.RED.value}❌ Fatal error: {e}{Color.RESET.value}")
        sys.exit(1)

if __name__ == "__main__":
    main()