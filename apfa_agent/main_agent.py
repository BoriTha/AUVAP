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
from typing import Optional, List

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
from apfa_agent.simple_agent import SimpleHeuristicAgent
from core.llm_client import UniversalLLMClient
from core.executor import CowboyExecutor
from msf_wrapper import MetasploitWrapper
from tool_manager import ToolManager
from environment import PentestingEnv
from rag_manager import RAGManager
from llm_only_mode import SmartTriageAgent as LLMOnlyMode # Aliasing SmartTriageAgent
from config.safety import is_running_in_vm, SecurityError
from report_generator import ReportGenerator

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
    open_port_list = []
    for host in nmap_results.get('hosts', []):
        for service in host.get('services', []):
            if service.get('state') == 'open':
                open_ports += 1
                open_port_list.append(service.get('port'))
                
    print(f"✓ Found {open_ports} open ports: {open_port_list}")
    
    # DEBUG: Print nmap results summary
    print(f"DEBUG: Nmap results keys: {nmap_results.keys()}")
    if 'hosts' in nmap_results:
        print(f"DEBUG: Hosts found: {len(nmap_results['hosts'])}")
        for h in nmap_results['hosts']:
            print(f"DEBUG: Host {h.get('ip')} has {len(h.get('services', []))} services")
            # Print first few services for verification
            for svc in h.get('services', [])[:5]:
                print(f"  DEBUG: Port {svc.get('port')} ({svc.get('service')}) - state: {svc.get('state')}")

    if open_ports == 0:
        print(" Warning: No open ports found. Agent may have nothing to do.")
        
        if not force_rescan:
            print("Cached scan returned no results. Forcing live scan...")
            return phase_0_scan(config, force_rescan=True)
        
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
    
    # SmartTriageAgent now handles report generation internally
    mode = LLMOnlyMode(config_path=config_path, config=config)
    results = mode.run(classified_json_path=apfa_path, nmap_results=nmap_results)
    
    # NOTE: Report generation is now handled by SmartTriageAgent.run()
    # No need to duplicate report generation here

def train_mode(config: dict, config_path: str, timesteps: int = None, apfa_path: str = None):
    """Training mode: Train PPO agent"""
    print("\n🎓 MODE: TRAINING (Hybrid RL + LLM)")
    
    # Setup
    nmap_results = phase_0_scan(config)
    if not apfa_path:
        apfa_path = phase_1_enrichment(config)
    else:
        print(f"Using provided APFA data: {apfa_path}")
    
    # Build graph
    mapper = TerrainMapper()
    graph = mapper.build_graph(nmap_results)
    
    # Create state manager
    state_mgr = StateManager(graph=graph, apfa_data_path=apfa_path)
    
    # Initialize components
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_lib_path = os.path.join(project_root, "data/agent_results/skill_library.json")
    
    tool_mgr = ToolManager(
        skill_library_path=skill_lib_path,
        msf_wrapper=MetasploitWrapper(config_path),
        max_failures=config.get('skill_library', {}).get('max_failures', 3)
    )
    
    llm = UniversalLLMClient(config)
    executor = CowboyExecutor(config)
    
    # Create environment
    env = PentestingEnv(
        state_manager=state_mgr,
        tool_manager=tool_mgr,
        llm_client=llm,
        executor=executor,
        max_steps=50,
        skill_persistence=config.get('mode', {}).get('train', {}).get('skill_persistence', 'read_write')
    )
    
    # Create SimpleHeuristicAgent (replacing PPO)
    agent = SimpleHeuristicAgent(state_mgr, tool_mgr, llm, executor, config_path)
    agent.set_environment(env)
    
    # Train (simulated episodes to gather skills)
    print("\n" + "="*60)
    print("TRAINING AGENT")
    print("="*60)
    
    if timesteps is None:
        timesteps = config.get('agent', {}).get('total_timesteps', 10000)
    
    print(f"Training for {timesteps} timesteps (heuristic agent)...")
    train_metrics = agent.train(total_timesteps=timesteps)
    
    print("\nTraining complete!")
    print(f"Training metrics: {train_metrics}")
    
    # Generate training report
    report_gen = ReportGenerator()
    report = report_gen.generate_train_report(
        config=config,
        tool_manager=tool_mgr,
        training_timesteps=timesteps,
        nmap_results=nmap_results,
        agent=agent
    )
    
    # Print skill library stats
    tool_mgr.print_stats()

def hybrid_mode(config: dict, config_path: str, target_ip: str = None, apfa_path: str = None, scoped_ports: list = None):
    """Hybrid mode: RL + LLM + Skill Library"""
    print("\nMODE: HYBRID (RL + LLM + Skill Library)")
    
    if target_ip:
        if 'target' not in config: config['target'] = {}
        config['target']['ip'] = target_ip
    
    # Setup (same as training)
    nmap_results = phase_0_scan(config)
    if not apfa_path:
        apfa_path = phase_1_enrichment(config)
    else:
        print(f"Using provided APFA data: {apfa_path}")
    
    mapper = TerrainMapper()
    graph = mapper.build_graph(nmap_results)
    
    # DEBUG: Verify graph was built correctly
    print(f"\nDEBUG: Graph built with {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    service_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'service']
    open_services = [n for n, d in graph.nodes(data=True) if d.get('type') == 'service' and d.get('state') == 'open']
    print(f"DEBUG: Service nodes: {len(service_nodes)}, Open services: {len(open_services)}")
    
    # Initialize StateManager with scoped ports if provided
    state_mgr = StateManager(graph=graph, apfa_data_path=apfa_path, tracked_ports=scoped_ports)
    
    # CRITICAL: Validate that scoped ports are actually exploitable
    available_actions = state_mgr.get_available_actions()
    if len(available_actions) == 0:
        print("\n" + "="*60)
        print("⚠️  ERROR: No exploitable ports available!")
        print("="*60)
        if scoped_ports:
            print(f"Scoped ports requested: {scoped_ports}")
        print(f"Tracked ports: {state_mgr.tracked_ports}")
        open_service_ports = sorted([int(d.get('port')) for n,d in graph.nodes(data=True) 
                                     if d.get('type')=='service' and d.get('state')=='open'])
        print(f"Ports found in Nmap scan: {open_service_ports}")
        
        print("\n🔍 Possible causes:")
        print("1. Scoped ports from vulnerability scan don't match current network state")
        print("2. Ports were closed/filtered between vulnerability scan and Nmap scan")
        print("3. Nmap scan was incomplete or filtered by firewall")
        print("4. Using vulnerabilities from different host than target IP")
        
        if scoped_ports and open_service_ports:
            print(f"\n💡 Suggestion: The following ports ARE open and exploitable:")
            matching = [p for p in open_service_ports if p not in scoped_ports]
            if matching:
                print(f"   {matching[:10]}")
                response = input("\nExpand scope to all open ports from scan? (y/N): ").strip().lower()
                if response == 'y':
                    print(f"✓ Expanding scope from {len(scoped_ports)} to {len(open_service_ports)} ports")
                    # Recreate StateManager with all ports
                    state_mgr = StateManager(graph=graph, apfa_data_path=apfa_path, tracked_ports=open_service_ports)
                    available_actions = state_mgr.get_available_actions()
                    print(f"✓ Now tracking {len(available_actions)} exploitable ports")
                else:
                    print("\n❌ Cannot proceed without exploitable ports. Exiting.")
                    return
        else:
            print("\n❌ Cannot proceed without exploitable ports. Exiting.")
            return
    else:
        print(f"\n✓ Ready: {len(available_actions)} exploitable ports available")
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_lib_path = os.path.join(project_root, "data/agent_results/skill_library.json")
    
    tool_mgr = ToolManager(
        skill_library_path=skill_lib_path,
        msf_wrapper=MetasploitWrapper(config_path),
        max_failures=config.get('skill_library', {}).get('max_failures', 3)
    )
    
    llm = UniversalLLMClient(config)
    executor = CowboyExecutor(config)
    
    env = PentestingEnv(
        state_manager=state_mgr,
        tool_manager=tool_mgr,
        llm_client=llm,
        executor=executor,
        max_steps=50,
        skill_persistence=config.get('mode', {}).get('hybrid', {}).get('skill_persistence', 'read_write')
    )
    
    agent = SimpleHeuristicAgent(state_mgr, tool_mgr, llm, executor, config_path)
    agent.set_environment(env)
    
    # Check if model needs re-initialization due to dimension change (no-op for heuristic)
    if scoped_ports:
        print("Scoped mode active: Heuristic agent ready for dynamic scope.")
        agent.initialize_model(force_new=True)
    
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
        # Heuristic agent selection
        try:
            action, _ = agent.predict(obs, deterministic=False)
        except Exception:
            # Fallback to random action
            action = env.action_space.sample()

        
        # Decode action for display
        try:
            port_index, method = env._decode_action(action)
            port_str = state_mgr.tracked_ports[port_index] if port_index is not None and port_index < len(state_mgr.tracked_ports) else 'N/A'
            print(f"Agent selected: Port {port_str}, Method: {method}")
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
    
    # Generate report using shared report generator
    report_gen = ReportGenerator()
    report = report_gen.generate_hybrid_report(
        config=config,
        nmap_results=nmap_results,
        state_manager=state_mgr,
        tool_manager=tool_mgr,
        llm_client=llm,
        env=env
    )
    
    # Print method usage stats
    print(f"  Method usage: LLM={env.method_stats.get('llm_generate',0)}, "
          f"Cached={env.method_stats.get('cached_skill',0)}, MSF={env.method_stats.get('metasploit',0)}")

def eval_mode(config: dict, config_path: str, n_episodes: int = 10, apfa_path: str = None):
    """Evaluation mode"""
    print("\nMODE: EVALUATION")
    
    # Setup (same as hybrid)
    nmap_results = phase_0_scan(config)
    if not apfa_path:
        apfa_path = phase_1_enrichment(config)
    else:
        print(f"Using provided APFA data: {apfa_path}")
    
    mapper = TerrainMapper()
    graph = mapper.build_graph(nmap_results)
    
    # Create state manager
    state_mgr = StateManager(graph=graph, apfa_data_path=apfa_path)
    
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    skill_lib_path = os.path.join(project_root, "data/agent_results/skill_library.json")
    
    tool_mgr = ToolManager(
        skill_library_path=skill_lib_path,
        msf_wrapper=MetasploitWrapper(config_path),
        max_failures=config.get('skill_library', {}).get('max_failures', 3)
    )
    
    llm = UniversalLLMClient(config)
    executor = CowboyExecutor(config)
    
    env = PentestingEnv(
        state_manager=state_mgr,
        tool_manager=tool_mgr,
        llm_client=llm,
        executor=executor,
        max_steps=50,
        skill_persistence=config.get('mode', {}).get('hybrid', {}).get('skill_persistence', 'read_write')
    )
    
    agent = SimpleHeuristicAgent(state_mgr, tool_mgr, llm, executor, config_path)
    agent.set_environment(env)
    
    print(f"\nRunning {n_episodes} evaluation episodes...\n")
    
    # Evaluate agent
    eval_results = agent.evaluate(n_episodes=n_episodes)
    
    # Generate evaluation report
    report_gen = ReportGenerator()
    report = report_gen.generate_eval_report(
        config=config,
        eval_results=eval_results,
        n_episodes=n_episodes,
        tool_manager=tool_mgr
    )

def generate_report(config, nmap_results, state_mgr, tool_mgr, llm, env) -> dict:
    """
    DEPRECATED: Use ReportGenerator.generate_hybrid_report() instead.
    
    This function is kept for backward compatibility but is no longer used.
    All modes now use the shared ReportGenerator class for consistent reporting.
    """
    import warnings
    warnings.warn(
        "generate_report() is deprecated. Use ReportGenerator.generate_hybrid_report() instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
    # Delegate to new report generator
    report_gen = ReportGenerator()
    return report_gen.generate_hybrid_report(config, nmap_results, state_mgr, tool_mgr, llm, env)

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
        default='apfa_agent/config/agent_config.yaml',
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
    
    # Resolve config path if needed (fixes issue where relative path works for load_config but fails later)
    if not os.path.exists(args.config):
        alt_path = os.path.join(os.path.dirname(__file__), args.config)
        if os.path.exists(alt_path):
            args.config = alt_path
    
    # Load config
    print(f"Loading config: {args.config}")
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading config: {e}")
        # Fallback or exit
        sys.exit(1)
    
    # Override target if specified in CLI
    if args.target:
        print(f"Overriding target IP: {args.target}")
        if 'target' not in config:
            config['target'] = {}
        config['target']['ip'] = args.target
    
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
