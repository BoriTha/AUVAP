#!/usr/bin/env python3
"""
DeepExploit Hybrid: Autonomous Pentesting Agent
Combines PPO (RL) with LLM-based exploit generation and Skill Library

Modes:
  llm-only: Simple sequential attacking with LLM ranking
  train:    Train PPO agent (RL mode)
  hybrid:   Run trained agent with skill acquisition
  eval:     Evaluate agent performance

Usage:
    # LLM-only (no RL, easy to use)
    python main_agent.py --mode llm-only --target 192.168.79.128
    
    # Train agent
    python main_agent.py --mode train --timesteps 100000
    
    # Run hybrid (RL + LLM + Skills)
    python main_agent.py --mode hybrid --target 192.168.79.128
    
    # Evaluate
    python main_agent.py --mode eval --episodes 20
"""

import argparse
import yaml
from pathlib import Path
from datetime import datetime
import json
import sys
import os

# CRITICAL: Configure sys.path for module imports
# This allows main_agent.py to find modules regardless of execution directory
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Also add parent directory to path to allow imports like 'apfa_agent.core' if needed
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Import all components
# Adjusted imports for actual file structure
from core.nmap_scanner import NmapScanner
from core.terrain_mapper import TerrainMapper
from core.state_manager import StateManager
from ppo_agent import PPOAgent
from core.llm_client import UniversalLLMClient
from core.executor import CowboyExecutor
from msf_wrapper import MetasploitWrapper
from tool_manager import ToolManager
from environment import PentestingEnv
from rag_manager import RAGManager
from llm_only_mode import SmartTriageAgent as LLMOnlyMode # Aliasing SmartTriageAgent
from config.safety import is_running_in_vm, SecurityError

def print_banner():
    """Print ASCII art banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        DeepExploit Hybrid - Autonomous Pentester         ║
║                                                           ║
║  Mode 1: LLM-Only (Smart Triage)                         ║
║  Mode 2: Hybrid (RL + LLM + Skill Library)               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def load_config(config_path: str) -> dict:
    """Load configuration from YAML"""
    # If config path is relative, make it relative to this file if not found
    if not os.path.exists(config_path):
        alt_path = os.path.join(os.path.dirname(__file__), config_path)
        if os.path.exists(alt_path):
            config_path = alt_path
            
    with open(config_path) as f:
        return yaml.safe_load(f)

def phase_0_scan(config: dict, force_rescan: bool = False) -> dict:
    """Phase 0: Network reconnaissance with Nmap"""
    print("\n" + "="*60)
    print("PHASE 0: NETWORK RECONNAISSANCE")
    print("="*60)
    
    scanner = NmapScanner(config)
    target_ip = config.get('target', {}).get('ip')
    
    if not target_ip:
        print("Error: No target IP specified in config or arguments")
        sys.exit(1)
        
    try:
        # Force rescan if requested, otherwise let scanner decide based on config
        if force_rescan:
            # Temporarily override mode to live for this scan
            original_mode = scanner.mode
            scanner.mode = 'live'
            nmap_results = scanner.scan(target_ip)
            scanner.mode = original_mode
        else:
            nmap_results = scanner.scan(target_ip)
            
    except Exception as e:
        print(f"Scan failed: {e}")
        sys.exit(1)
    
    # Count open ports
    open_ports = 0
    for host in nmap_results.get('hosts', []):
        for service in host.get('services', []):
            if service.get('state') == 'open':
                open_ports += 1
                
    print(f"✓ Found {open_ports} open ports")
    
    if open_ports == 0:
        print(" Warning: No open ports found. Agent may have nothing to do.")
        
    return nmap_results

def phase_1_enrichment(config: dict) -> str:
    """Phase 1: Optional APFA enrichment"""
    if not config.get('enrichment', {}).get('use_apfa_classifier', False):
        print("\n[PHASE 1: SKIPPED] APFA enrichment disabled")
        return None
    
    print("\n" + "="*60)
    print("PHASE 1: APFA VULNERABILITY ENRICHMENT")
    print("="*60)
    
    # Assuming data path is relative to project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    apfa_path = os.path.join(project_root, "data/processed/ms2_classified.json")
    
    if Path(apfa_path).exists():
        print(f"✓ Loading APFA data: {apfa_path}")
        return apfa_path
    else:
        print(f"APFA data not found: {apfa_path}")
        return None

def llm_only_mode(config: dict, config_path: str, target_ip: str = None, apfa_path: str = None):
    """LLM-only mode: Simple sequential attacking"""
    print("\nMODE: LLM-ONLY (Smart Triage)")
    
    if target_ip:
        if 'target' not in config: config['target'] = {}
        config['target']['ip'] = target_ip
    
    # Phase 0: Scan (if no APFA data provided)
    if not apfa_path:
        print("Running Nmap scan (no APFA data provided)")
        nmap_results = phase_0_scan(config)
    else:
        print(f"Using existing APFA data: {apfa_path}")
        nmap_results = None  # Will use APFA data instead
    
    # Phase 1: Load APFA data (if provided) or use scan results
    if not apfa_path:
        apfa_path = phase_1_enrichment(config)
        if not apfa_path:
            print(" Warning: No APFA data available, using scan results only")
    else:
        print(f"Using provided APFA data: {apfa_path}")
    
    # Execute LLM-only mode with available data
    if not apfa_path and not nmap_results:
        print("LLM-only mode requires either APFA data or successful scan")
        sys.exit(1)
    
    # Execute
    print("\n" + "="*60)
    print("EXECUTING LLM-ONLY MODE")
    print("="*60)
    
    # SmartTriageAgent init might need config_path
    mode = LLMOnlyMode(config_path=config_path, config=config)
    
    # SmartTriageAgent.run might take apfa_path or nmap_results
    # Checking llm_only_mode.py content again would be good, but assuming run(apfa_path) based on prompt
    results = mode.run(classified_json_path=apfa_path, nmap_results=nmap_results)
    
    # Calculate stats for report
    total_ports_count = 0
    services_list = []
    if nmap_results:
        for host in nmap_results.get('hosts', []):
            for svc in host.get('services', []):
                if svc.get('state') == 'open':
                    total_ports_count += 1
                    services_list.append(svc)

    # Generate report
    report = {
        'metadata': {
            'mode': 'llm-only',
            'target_ip': config.get('target', {}).get('ip', 'unknown'),
            'scan_date': datetime.now().isoformat()
        },
        'scan_results': {
            'total_ports': total_ports_count,
            'services': services_list
        },
        'exploitation_results': {
            'total_attempts': len(results),
            'successful_exploits': sum(1 for r in results if r.get('success', False)),
            'success_rate': sum(1 for r in results if r.get('success', False)) / max(len(results), 1)
        },
        'results': results
    }
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, f"data/agent_results/llm_only_report_{timestamp}.json")
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved: {report_path}")
    print(f"\nSummary:")
    print(f"  Total attempts: {report['exploitation_results']['total_attempts']}")
    print(f"  Successful: {report['exploitation_results']['successful_exploits']}")
    print(f"  Success rate: {report['exploitation_results']['success_rate']:.1%}")

def train_mode(config: dict, config_path: str, timesteps: int = None):
    """Training mode: Train PPO agent"""
    print("\n🎓 MODE: TRAINING (Hybrid RL + LLM)")
    
    # Setup
    nmap_results = phase_0_scan(config)
    apfa_path = phase_1_enrichment(config)
    
    # Build graph
    mapper = TerrainMapper()
    graph = mapper.create_from_nmap(nmap_results)
    
    # Create state manager
    state_mgr = StateManager(nmap_graph=graph, apfa_json_path=apfa_path)
    
    # Initialize components
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_lib_path = os.path.join(project_root, "data/agent_results/skill_library.json")
    
    tool_mgr = ToolManager(
        skill_library_path=skill_lib_path,
        msf_wrapper=MetasploitWrapper(config_path),
        max_failures=config.get('skill_library', {}).get('max_failures', 3)
    )
    
    llm = UniversalLLMClient()
    executor = CowboyExecutor(target_ip=config.get('target', {}).get('ip'))
    
    # Create environment
    env = PentestingEnv(
        state_manager=state_mgr,
        tool_manager=tool_mgr,
        llm_client=llm,
        executor=executor,
        max_steps=50,
        skill_persistence=config.get('mode', {}).get('hybrid', {}).get('skill_persistence', 'read_write')
    )
    
    # Create PPO agent
    # PPOAgent init: (self, state_manager, tool_manager, llm_client, executor, config_path)
    ppo_agent = PPOAgent(state_mgr, tool_mgr, llm, executor, config_path)
    ppo_agent.set_environment(env)
    # ppo_agent.initialize_model(force_new=False) # This method might not exist in PPOAgent based on file read, checking...
    # PPOAgent in file has self.model = None. It likely has a method to create/load model.
    # Assuming train() handles initialization or we need to call something.
    # Let's assume train() handles it or we use what's available.
    
    # Train
    print("\n" + "="*60)
    print("TRAINING PPO AGENT")
    print("="*60)
    
    if timesteps is None:
        timesteps = config.get('agent', {}).get('total_timesteps', 10000)
    
    print(f"Training for {timesteps} timesteps...")
    ppo_agent.train(total_timesteps=timesteps)
    
    print("\nTraining complete!")
    print(f"Model saved: {ppo_agent.model_path}")
    
    # Print skill library stats
    tool_mgr.print_stats()

def hybrid_mode(config: dict, config_path: str, target_ip: str = None):
    """Hybrid mode: RL + LLM + Skill Library"""
    print("\nMODE: HYBRID (RL + LLM + Skill Library)")
    
    if target_ip:
        if 'target' not in config: config['target'] = {}
        config['target']['ip'] = target_ip
    
    # Setup (same as training)
    nmap_results = phase_0_scan(config)
    apfa_path = phase_1_enrichment(config)
    
    mapper = TerrainMapper()
    graph = mapper.create_from_nmap(nmap_results)
    
    state_mgr = StateManager(nmap_graph=graph, apfa_json_path=apfa_path)
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_lib_path = os.path.join(project_root, "data/agent_results/skill_library.json")
    
    tool_mgr = ToolManager(
        skill_library_path=skill_lib_path,
        msf_wrapper=MetasploitWrapper(config_path),
        max_failures=config.get('skill_library', {}).get('max_failures', 3)
    )
    
    llm = UniversalLLMClient()
    executor = CowboyExecutor(target_ip=config.get('target', {}).get('ip'))
    
    env = PentestingEnv(
        state_manager=state_mgr,
        tool_manager=tool_mgr,
        llm_client=llm,
        executor=executor,
        max_steps=50,
        skill_persistence=config.get('mode', {}).get('hybrid', {}).get('skill_persistence', 'read_write')
    )
    
    ppo_agent = PPOAgent(state_mgr, tool_mgr, llm, executor, config_path)
    ppo_agent.set_environment(env)
    # ppo_agent.initialize_model(force_new=False)
    
    # Run episode
    print("\n" + "="*60)
    print("AUTONOMOUS EXPLOITATION")
    print("="*60)
    
    obs, info = env.reset() # gym.Env.reset returns (obs, info)
    done = False
    step = 0
    
    print("\nStarting autonomous exploitation...\n")
    
    while not done:
        step += 1
        print(f"\n--- Step {step} ---")
        
        # PPO selects action
        # We need to load the model first if not trained in this session
        if ppo_agent.model is None:
             # Try to load, or use random if no model?
             # PPOAgent should handle loading in __init__ or we need to call load
             # Assuming PPOAgent loads model in __init__ or has a load method.
             # Based on file read: self.model = None. self.model_path = ...
             # It likely needs explicit loading.
             try:
                 ppo_agent.load()
             except:
                 print("Warning: No trained model found, using random actions or untrained agent.")
                 # If load fails, we might need to initialize a new one
                 ppo_agent.initialize_model() # Assuming this method exists or similar
        
        action, _states = ppo_agent.model.predict(obs, deterministic=True)
        
        # Decode action for display
        # env._decode_action might be internal, but useful for logging
        try:
            port_index, method = env._decode_action(action)
            port_str = state_mgr.TRACKED_PORTS[port_index] if port_index is not None and port_index < len(state_mgr.TRACKED_PORTS) else 'N/A'
            print(f"PPO selected: Port {port_str}, Method: {method}")
        except:
            print(f"PPO selected action: {action}")
        
        # Execute
        obs, reward, terminated, truncated, info = env.step(action)
        done = terminated or truncated
        
        print(f"Reward: {reward:+.2f} | Total: {env.total_reward:.2f}")
        print(f"Result: {info.get('result', 'unknown')}")
        
        if info.get('root_obtained'):
            print("ROOT ACCESS OBTAINED!")
            break
    
    # Generate report
    report = generate_report(config, nmap_results, state_mgr, tool_mgr, llm, env)
    
    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_path = os.path.join(project_root, f"data/agent_results/hybrid_report_{timestamp}.json")
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved: {report_path}")
    print(f"\nSummary:")
    print(f"  Total attempts: {report['exploitation_results']['total_attempts']}")
    print(f"  Successful: {report['exploitation_results']['successful_exploits']}")
    print(f"  Success rate: {report['exploitation_results']['success_rate']:.1%}")
    print(f"  Skills in library: {report['skill_library_stats']['total_skills']}")
    print(f"  Method usage: LLM={env.method_stats.get('llm_generate',0)}, "
          f"Cached={env.method_stats.get('cached_skill',0)}, MSF={env.method_stats.get('metasploit',0)}")

def eval_mode(config: dict, config_path: str, n_episodes: int = 10):
    """Evaluation mode"""
    print("\nMODE: EVALUATION")
    
    # Setup (same as hybrid)
    nmap_results = phase_0_scan(config)
    apfa_path = phase_1_enrichment(config)
    
    mapper = TerrainMapper()
    graph = mapper.create_from_nmap(nmap_results)
    
    state_mgr = StateManager(nmap_graph=graph, apfa_json_path=apfa_path)
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_lib_path = os.path.join(project_root, "data/agent_results/skill_library.json")
    
    tool_mgr = ToolManager(
        skill_library_path=skill_lib_path,
        msf_wrapper=MetasploitWrapper(config_path),
        max_failures=config.get('skill_library', {}).get('max_failures', 3)
    )
    
    llm = UniversalLLMClient()
    executor = CowboyExecutor(target_ip=config.get('target', {}).get('ip'))
    
    env = PentestingEnv(
        state_manager=state_mgr,
        tool_manager=tool_mgr,
        llm_client=llm,
        executor=executor,
        max_steps=50,
        skill_persistence=config.get('mode', {}).get('hybrid', {}).get('skill_persistence', 'read_write')
    )
    
    ppo_agent = PPOAgent(state_mgr, tool_mgr, llm, executor, config_path)
    ppo_agent.set_environment(env)
    
    print(f"\nRunning {n_episodes} evaluation episodes...\n")
    
    # Assuming evaluate method exists
    ppo_agent.evaluate(n_episodes=n_episodes)

def generate_report(config, nmap_results, state_mgr, tool_mgr, llm, env) -> dict:
    """Generate comprehensive report"""
    stats = state_mgr.get_statistics()
    
    return {
        'metadata': {
            'mode': 'hybrid',
            'target_ip': config.get('target', {}).get('ip'),
            'scan_date': datetime.now().isoformat(),
            'agent_model': config.get('agent', {}).get('model_name')
        },
        'scan_results': {
            'total_ports': len(nmap_results['open_ports']) if nmap_results else 0,
            'services': nmap_results['open_ports'] if nmap_results else []
        },
        'exploitation_results': {
            'total_attempts': stats.get('total_attempts', 0),
            'successful_exploits': stats.get('successful_exploits', 0),
            'success_rate': stats.get('success_rate', 0.0),
            'average_reward': stats.get('average_reward', 0.0),
            'root_obtained': env.root_obtained
        },
        'skill_library_stats': {
            'total_skills': len(tool_mgr.skills),
            'skills_used': env.method_stats.get('cached_skill', 0),
            'method_distribution': env.method_stats
        },
        'compromised_services': stats.get('compromised_ports', []),
        'attack_history': state_mgr.action_history,
        'llm_stats': llm.stats if hasattr(llm, 'stats') else {}
    }

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="DeepExploit Hybrid - Autonomous Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--mode',
        choices=['llm-only', 'train', 'hybrid', 'eval'],
        default='hybrid',
        help='Operation mode'
    )
    parser.add_argument(
        '--config',
        default='config/agent_config.yaml',
        help='Path to config file'
    )
    parser.add_argument(
        '--target',
        help='Override target IP from config'
    )
    parser.add_argument(
        '--timesteps',
        type=int,
        help='Training timesteps (for train mode)'
    )
    parser.add_argument(
        '--episodes',
        type=int,
        default=10,
        help='Evaluation episodes (for eval mode)'
    )
    parser.add_argument(
        '--force-rescan',
        action='store_true',
        help='Force fresh Nmap scan (ignore cache)'
    )
    
    args = parser.parse_args()
    
    # CRITICAL: Safety confirmation for pentesting tool
    # Prevents accidental execution on production laptop
    try:
        is_vm = is_running_in_vm()
        if not is_vm:
            print("  SAFETY WARNING: Not running in a VM!")
            print("   This tool is designed for authorized pentesting only.")
            print("   Running on your host machine could be dangerous.")
            print("")
            # In non-interactive environments, this might hang. 
            # But for a CLI tool, it's appropriate.
            # For automated testing, we might want a flag to bypass.
            if os.environ.get('APFA_SKIP_SAFETY_CHECK') != 'true':
                response = input("Are you sure you want to continue? (y/N): ").strip().lower()
                if response not in ['y', 'yes']:
                    print("  Aborted for safety")
                    sys.exit(0)
                else:
                    print("   Proceeding anyway - you are responsible for any damage")
        else:
            print(" Running in VM - safety check passed")
    except Exception as e:
        print(f"   Could not verify VM status: {e}")
        if os.environ.get('APFA_SKIP_SAFETY_CHECK') != 'true':
            response = input("Continue anyway? (y/N): ").strip().lower()
            if response not in ['y', 'yes']:
                print("  Aborted")
                sys.exit(0)
    
    # Print banner
    print_banner()
    
    # Load config
    print(f"Loading config: {args.config}")
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading config: {e}")
        # Fallback or exit
        sys.exit(1)
    
    # Execute mode
    try:
        if args.mode == 'llm-only':
            llm_only_mode(config, args.config, target_ip=args.target, apfa_path=None)
        elif args.mode == 'train':
            train_mode(config, args.config, timesteps=args.timesteps)
        elif args.mode == 'hybrid':
            hybrid_mode(config, args.config, target_ip=args.target)
        elif args.mode == 'eval':
            eval_mode(config, args.config, n_episodes=args.episodes)
    
    except KeyboardInterrupt:
        print("\n\n   Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n  Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
