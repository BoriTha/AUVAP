"""
Unified Configuration Management System
Centralized configuration handling for APFA CLI
"""

import os
import sys
import json
import yaml
from typing import Dict, Any, Optional, Union
from pathlib import Path

# Add paths for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

try:
    from ui.components import MenuSystem, Color, UIComponent
except ImportError:
    sys.path.insert(0, os.path.join(parent_dir, 'ui'))
    from components import MenuSystem, Color, UIComponent

class ConfigManager(UIComponent):
    """Unified configuration management system"""
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__()
        self.menu_system = MenuSystem()
        
        # Configuration paths
        if config_path:
            self.config_path = config_path
        else:
            self.config_path = os.path.join(
                parent_dir, 'apfa_agent/config/agent_config.yaml'
            )
            
        self.user_config_path = os.path.join(parent_dir, 'config/user_config.yaml')
        self.backup_config_path = os.path.join(parent_dir, 'config/backup_config.yaml')
        
        # Configuration data
        self.config = {}
        self.default_config = self._get_default_config()
        
        # Load configurations
        self.load_config()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from files"""
        try:
            # Start with default config
            self.config = self.default_config.copy()
            
            # Load main config if exists
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    main_config = yaml.safe_load(f) or {}
                    self._deep_merge(self.config, main_config)
                    
            # Load user config if exists (overrides main config)
            if os.path.exists(self.user_config_path):
                with open(self.user_config_path, 'r') as f:
                    user_config = yaml.safe_load(f) or {}
                    self._deep_merge(self.config, user_config)
                    
            return self.config
            
        except Exception as e:
            print(f"{Color.RED.value}❌ Error loading config: {e}{Color.RESET.value}")
            return self.default_config
            
    def save_config(self, config: Optional[Dict[str, Any]] = None, 
                   backup: bool = True) -> bool:
        """Save configuration to file"""
        try:
            if config:
                self.config = config
                
            # Create backup if requested
            if backup and os.path.exists(self.config_path):
                self._create_backup()
                
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            # Save main config
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, sort_keys=False, default_flow_style=False)
                
            print(f"{Color.GREEN.value}✅ Configuration saved{Color.RESET.value}")
            return True
            
        except Exception as e:
            print(f"{Color.RED.value}❌ Error saving config: {e}{Color.RESET.value}")
            return False
            
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
            
    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        # Set the final value
        config[keys[-1]] = value
        
    def reset_to_defaults(self) -> Dict[str, Any]:
        """Reset configuration to defaults"""
        self.config = self.default_config.copy()
        return self.config
        
    def show_config_menu(self) -> Dict[str, Any]:
        """Display interactive configuration menu"""
        while True:
            self.clear_screen()
            self.menu_system.show_banner("⚙️  Settings & Configuration")
            
            # Show current config summary
            self._show_config_summary()
            
            # Menu options
            options = [
                {'icon': '[NET]', 'title': 'Network Settings', 'description': 'Target IP, scan speed, timeouts'},
                {'icon': '[LLM]', 'title': 'LLM Configuration', 'description': 'Models, API keys, parameters'},
                {'icon': '[SAFE]', 'title': 'Safety & Limits', 'description': 'VM checks, allowed targets, time limits'},
                {'icon': '[FILE]', 'title': 'File Locations', 'description': 'Paths for scans, reports, logs'},
                {'icon': '[ADV]', 'title': 'Advanced Settings', 'description': 'Expert configuration options'},
                {'icon': '[SAVE]', 'title': 'Save Configuration', 'description': 'Save current settings'},
                {'icon': '[RESET]', 'title': 'Reset to Defaults', 'description': 'Restore default settings'},
                {'icon': '[EXPORT]', 'title': 'Export Configuration', 'description': 'Export to file'},
                {'icon': '[IMPORT]', 'title': 'Import Configuration', 'description': 'Import from file'},
                {'icon': '[BACK]', 'title': 'Back to Main Menu', 'description': 'Return to main menu'}
            ]
            
            choice = self.menu_system.show_menu("⚙️  Configuration", options, show_back=False)
            
            if choice == 0:  # Network Settings
                self._configure_network()
            elif choice == 1:  # LLM Configuration
                self._configure_llm()
            elif choice == 2:  # Safety & Limits
                self._configure_safety()
            elif choice == 3:  # File Locations
                self._configure_files()
            elif choice == 4:  # Advanced Settings
                self._configure_advanced()
            elif choice == 5:  # Save
                self.save_config()
                input("Press Enter to continue...")
            elif choice == 6:  # Reset
                if self._confirm_reset():
                    self.reset_to_defaults()
                    print(f"{Color.YELLOW.value}🔄 Configuration reset to defaults{Color.RESET.value}")
                    input("Press Enter to continue...")
            elif choice == 7:  # Export
                self._export_config()
            elif choice == 8:  # Import
                self._import_config()
            elif choice == 9:  # Back
                break
                
        return self.config
        
    def _show_config_summary(self):
        """Display current configuration summary"""
        target = self.get('target.ip', 'Not set')
        model = self.get('llm.models.0.name', 'Not set')
        vm_check = self.get('safety.require_vm', False)
        scan_mode = self.get('scanning.mode', 'auto')
        
        summary = f"""
{Color.BOLD}📊 Current Configuration Summary:{Color.RESET}
   🎯 Target: {target}
   🤖 LLM Model: {model}
   🛡️  VM Check: {'✅ Enabled' if vm_check else '❌ Disabled'}
   🔍 Scan Mode: {scan_mode}
   📁 Reports: data/agent_results/

"""
        print(summary)
        
    def _configure_network(self):
        """Configure network settings"""
        self.clear_screen()
        print(f"{Color.BOLD}🌐 Network Settings{Color.RESET}")
        print("=" * 50)
        
        # Target IP
        current_target = self.get('target.ip', '')
        new_target = input(f"Target IP [{current_target}]: ").strip()
        if new_target:
            self.set('target.ip', new_target)
            
        # Scan mode
        current_mode = self.get('scanning.mode', 'auto')
        print(f"\nScan Mode:")
        print("1. Auto - Intelligent scanning")
        print("2. Fast - Quick scan")
        print("3. Thorough - Comprehensive scan")
        
        mode_choice = input(f"Scan mode [1-3] (current: {current_mode}): ").strip()
        mode_map = {'1': 'auto', '2': 'fast', '3': 'thorough'}
        if mode_choice in mode_map:
            self.set('scanning.mode', mode_map[mode_choice])
            
        # Nmap arguments
        current_args = self.get('scanning.live_scan.arguments', '-sV -sC --top-ports 1000 -T4')
        new_args = input(f"Nmap arguments [{current_args}]: ").strip()
        if new_args:
            self.set('scanning.live_scan.arguments', new_args)
            
        # Timeout
        current_timeout = self.get('scanning.live_scan.cache_duration', 3600)
        new_timeout = input(f"Cache duration in seconds [{current_timeout}]: ").strip()
        if new_timeout and new_timeout.isdigit():
            self.set('scanning.live_scan.cache_duration', int(new_timeout))
            
        print(f"{Color.GREEN.value}✅ Network settings updated{Color.RESET.value}")
        input("Press Enter to continue...")
        
    def _configure_llm(self):
        """Configure LLM settings"""
        self.clear_screen()
        print(f"{Color.BOLD}🤖 LLM Configuration{Color.RESET}")
        print("=" * 50)
        
        # Show current models
        models = self.get('llm.models', [])
        print(f"{Color.BOLD}Current Models:{Color.RESET}")
        for i, model in enumerate(models):
            status = "✅ Enabled" if model.get('enabled', False) else "❌ Disabled"
            print(f"  {i+1}. {model.get('name', 'Unknown')} ({model.get('provider', 'Unknown')}) - {status}")
            
        print(f"\n{Color.BOLD}Configuration Options:{Color.RESET}")
        print("1. Enable/Disable models")
        print("2. Configure API keys")
        print("3. Add new model")
        print("4. Set primary model")
        
        choice = input("Select option [1-4]: ").strip()
        
        if choice == '1':
            self._toggle_models()
        elif choice == '2':
            self._configure_api_keys()
        elif choice == '3':
            self._add_model()
        elif choice == '4':
            self._set_primary_model()
            
    def _configure_safety(self):
        """Configure safety settings"""
        self.clear_screen()
        print(f"{Color.BOLD}🛡️  Safety & Limits{Color.RESET}")
        print("=" * 50)
        
        # VM check
        current_vm = self.get('safety.require_vm', True)
        vm_choice = input(f"Require VM check (y/n) [{'y' if current_vm else 'n'}]: ").strip().lower()
        if vm_choice in ['y', 'n']:
            self.set('safety.require_vm', vm_choice == 'y')
            
        # Allowed targets
        current_targets = self.get('safety.allowed_targets', [])
        targets_str = ', '.join(current_targets) if current_targets else 'None'
        new_targets = input(f"Allowed targets (comma-separated) [{targets_str}]: ").strip()
        if new_targets:
            targets = [t.strip() for t in new_targets.split(',') if t.strip()]
            self.set('safety.allowed_targets', targets)
            
        # Execution timeout
        current_timeout = self.get('execution.timeout', 60)
        new_timeout = input(f"Execution timeout in seconds [{current_timeout}]: ").strip()
        if new_timeout and new_timeout.isdigit():
            self.set('execution.timeout', int(new_timeout))
            
        # Execution mode
        current_mode = self.get('execution.mode', 'safe')
        print(f"\nExecution Mode:")
        print("1. Safe - Information gathering only")
        print("2. Moderate - Safe exploits")
        print("3. Aggressive - All exploits")
        
        mode_choice = input(f"Execution mode [1-3] (current: {current_mode}): ").strip()
        mode_map = {'1': 'safe', '2': 'moderate', '3': 'aggressive'}
        if mode_choice in mode_map:
            self.set('execution.mode', mode_map[mode_choice])
            
        print(f"{Color.GREEN.value}✅ Safety settings updated{Color.RESET.value}")
        input("Press Enter to continue...")
        
    def _configure_files(self):
        """Configure file locations"""
        self.clear_screen()
        print(f"{Color.BOLD}📁 File Locations{Color.RESET}")
        print("=" * 50)
        
        locations = [
            ('scanning.live_scan.output_dir', 'Scan Results', 'data/scans'),
            ('agent_results_dir', 'Agent Results', 'data/agent_results'),
            ('temp_dir', 'Temporary Files', 'data/temp'),
            ('logs_dir', 'Log Files', 'logs')
        ]
        
        for key, name, default in locations:
            current = self.get(key, default)
            new_path = input(f"{name} directory [{current}]: ").strip()
            if new_path:
                self.set(key, new_path)
                
        print(f"{Color.GREEN.value}✅ File locations updated{Color.RESET.value}")
        input("Press Enter to continue...")
        
    def _configure_advanced(self):
        """Configure advanced settings"""
        self.clear_screen()
        print(f"{Color.BOLD}🔧 Advanced Settings{Color.RESET}")
        print("=" * 50)
        
        # Metasploit settings
        print(f"{Color.BOLD}Metasploit Configuration:{Color.RESET}")
        msf_enabled = self.get('metasploit.enabled', True)
        msf_choice = input(f"Enable Metasploit (y/n) [{'y' if msf_enabled else 'n'}]: ").strip().lower()
        if msf_choice in ['y', 'n']:
            self.set('metasploit.enabled', msf_choice == 'y')
            
        msf_host = self.get('metasploit.rpc_host', '127.0.0.1')
        new_host = input(f"Metasploit RPC host [{msf_host}]: ").strip()
        if new_host:
            self.set('metasploit.rpc_host', new_host)
            
        msf_port = self.get('metasploit.rpc_port', 55553)
        new_port = input(f"Metasploit RPC port [{msf_port}]: ").strip()
        if new_port and new_port.isdigit():
            self.set('metasploit.rpc_port', int(new_port))
            
        # RAG settings
        print(f"\n{Color.BOLD}RAG Configuration:{Color.RESET}")
        rag_enabled = self.get('rag.enabled', True)
        rag_choice = input(f"Enable RAG (y/n) [{'y' if rag_enabled else 'n'}]: ").strip().lower()
        if rag_choice in ['y', 'n']:
            self.set('rag.enabled', rag_choice == 'y')
            
        print(f"{Color.GREEN.value}✅ Advanced settings updated{Color.RESET.value}")
        input("Press Enter to continue...")
        
    def _toggle_models(self):
        """Toggle model enabled/disabled status"""
        models = self.get('llm.models', [])
        if not models:
            print("No models configured")
            input("Press Enter to continue...")
            return
            
        print(f"\nSelect model to toggle:")
        for i, model in enumerate(models):
            status = "Enabled" if model.get('enabled', False) else "Disabled"
            print(f"  {i+1}. {model.get('name', 'Unknown')} - {status}")
            
        try:
            choice = int(input("Enter model number: ")) - 1
            if 0 <= choice < len(models):
                current_state = models[choice].get('enabled', False)
                models[choice]['enabled'] = not current_state
                self.set('llm.models', models)
                new_state = "Enabled" if not current_state else "Disabled"
                print(f"Model {models[choice].get('name', 'Unknown')} {new_state}")
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")
            
        input("Press Enter to continue...")
        
    def _configure_api_keys(self):
        """Configure API keys"""
        print(f"\n{Color.BOLD}API Key Configuration:{Color.RESET}")
        print("API keys should be set as environment variables:")
        print("  • OPENROUTER_API_KEY")
        print("  • OPENAI_API_KEY")
        print("  • ANTHROPIC_API_KEY")
        print("\nTo set API keys:")
        print("  Linux/Mac: export API_KEY='your_key_here'")
        print("  Windows: set API_KEY=your_key_here")
        print("  Or add to your shell profile (.bashrc, .zshrc, etc.)")
        
        input("\nPress Enter to continue...")
        
    def _add_model(self):
        """Add new model configuration"""
        print(f"\n{Color.BOLD}Add New Model:{Color.RESET}")
        
        name = input("Model name: ").strip()
        if not name:
            return
            
        provider = input("Provider (ollama/openrouter/openai/anthropic): ").strip().lower()
        if provider not in ['ollama', 'openrouter', 'openai', 'anthropic']:
            print("Invalid provider")
            input("Press Enter to continue...")
            return
            
        model = input("Model identifier: ").strip()
        if not model:
            return
            
        endpoint = input("API endpoint (optional): ").strip()
        temperature = input("Temperature (0.0-1.0) [0.1]: ").strip() or "0.1"
        max_tokens = input("Max tokens [4096]: ").strip() or "4096"
        
        new_model = {
            'name': name,
            'provider': provider,
            'model': model,
            'temperature': float(temperature),
            'max_tokens': int(max_tokens),
            'enabled': True
        }
        
        if endpoint:
            new_model['endpoint'] = endpoint
            
        if provider in ['openrouter', 'openai', 'anthropic']:
            api_key_env = input("API key environment variable: ").strip()
            if api_key_env:
                new_model['api_key_env'] = api_key_env
                
        models = self.get('llm.models', [])
        models.append(new_model)
        self.set('llm.models', models)
        
        print(f"{Color.GREEN.value}✅ Model '{name}' added{Color.RESET.value}")
        input("Press Enter to continue...")
        
    def _set_primary_model(self):
        """Set primary model"""
        models = self.get('llm.models', [])
        enabled_models = [m for m in models if m.get('enabled', False)]
        
        if not enabled_models:
            print("No enabled models available")
            input("Press Enter to continue...")
            return
            
        print(f"\nSelect primary model:")
        for i, model in enumerate(enabled_models):
            print(f"  {i+1}. {model.get('name', 'Unknown')}")
            
        try:
            choice = int(input("Enter model number: ")) - 1
            if 0 <= choice < len(enabled_models):
                # Move selected model to front of list
                selected = enabled_models[choice]
                models.remove(selected)
                models.insert(0, selected)
                self.set('llm.models', models)
                print(f"Primary model set to: {selected.get('name', 'Unknown')}")
            else:
                print("Invalid selection")
        except ValueError:
            print("Invalid input")
            
        input("Press Enter to continue...")
        
    def _export_config(self):
        """Export configuration to file"""
        filename = input("Export filename [config_export.yaml]: ").strip() or "config_export.yaml"
        
        try:
            export_path = os.path.join(parent_dir, filename)
            with open(export_path, 'w') as f:
                yaml.dump(self.config, f, sort_keys=False, default_flow_style=False)
                
            print(f"{Color.GREEN.value}✅ Configuration exported to: {export_path}{Color.RESET.value}")
        except Exception as e:
            print(f"{Color.RED.value}❌ Export failed: {e}{Color.RESET.value}")
            
        input("Press Enter to continue...")
        
    def _import_config(self):
        """Import configuration from file"""
        filename = input("Import filename: ").strip()
        
        if not filename:
            return
            
        import_path = os.path.join(parent_dir, filename)
        
        if not os.path.exists(import_path):
            print(f"{Color.RED.value}❌ File not found: {import_path}{Color.RESET.value}")
            input("Press Enter to continue...")
            return
            
        try:
            with open(import_path, 'r') as f:
                imported_config = yaml.safe_load(f) or {}
                
            self._deep_merge(self.config, imported_config)
            print(f"{Color.GREEN.value}✅ Configuration imported successfully{Color.RESET.value}")
        except Exception as e:
            print(f"{Color.RED.value}❌ Import failed: {e}{Color.RESET.value}")
            
        input("Press Enter to continue...")
        
    def _confirm_reset(self) -> bool:
        """Confirm configuration reset"""
        print(f"{Color.YELLOW.value}⚠️  This will reset all settings to defaults{Color.RESET.value}")
        choice = input("Are you sure? (y/n): ").strip().lower()
        return choice == 'y'
        
    def _create_backup(self):
        """Create backup of current configuration"""
        try:
            import shutil
            shutil.copy2(self.config_path, self.backup_config_path)
        except Exception:
            pass  # Backup is optional
            
    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]):
        """Deep merge two dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
                
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'target': {
                'ip': '127.0.0.1',
                'description': 'Default Target'
            },
            'scanning': {
                'mode': 'auto',
                'nmap_xml': None,
                'live_scan': {
                    'enabled': True,
                    'arguments': '-sV -sC --top-ports 1000 -T4',
                    'output_dir': 'data/scans',
                    'cache_duration': 3600
                },
                'sudo': False
            },
            'enrichment': {
                'use_nessus': False,
                'nessus_file': None,
                'use_apfa_classifier': True
            },
            'agent': {
                'model_name': 'intelligent_metasploitable',
                'decision_strategy': 'heuristic',
                'max_steps': 50,
                'skill_persistence': 'persist_with_decay'
            },
            'llm': {
                'models': [
                    {
                        'name': 'dolphin-llama3',
                        'provider': 'ollama',
                        'model': 'dolphin-llama3',
                        'endpoint': 'http://localhost:11434',
                        'temperature': 0.1,
                        'max_tokens': 8192,
                        'timeout': 120,
                        'enabled': True
                    }
                ],
                'retry': {
                    'max_failures_per_model': 3,
                    'rotate_on_failure': True,
                    'retry_with_error_feedback': True,
                    'max_retries': 2
                }
            },
            'execution': {
                'mode': 'safe',
                'timeout': 60,
                'max_retries': 2
            },
            'safety': {
                'require_vm': True,
                'allowed_targets': ['192.168.79.128'],
                'forbidden_commands': ['rm -rf', 'format', 'del /f', 'dd if=', 'mkfs', '> /dev/sda']
            },
            'metasploit': {
                'enabled': True,
                'rpc_host': '127.0.0.1',
                'rpc_port': 55553,
                'rpc_ssl': False,
                'username': 'msf',
                'password': 'msf123',
                'auto_start': False
            },
            'rag': {
                'enabled': True,
                'embedding_model': 'all-MiniLM-L6-v2',
                'vector_db_path': 'data/agent_results/rag_exploits.pkl',
                'top_k': 5,
                'similarity_threshold': 0.5
            },
            'skill_library': {
                'enabled': True,
                'path': 'data/agent_results/skill_library.json',
                'max_failures': 3,
                'auto_save': True,
                'prioritize_cached': True
            }
        }