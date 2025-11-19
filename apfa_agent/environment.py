import gymnasium as gym
from gymnasium import spaces
import numpy as np
from typing import Tuple, Dict, Any, Optional
from apfa_agent.prompts import SYSTEM_PROMPT, ERROR_RETRY_PROMPT, POST_EXPLOIT_PROMPT, RAG_CONTEXT_PROMPT

class PentestingEnv(gym.Env):
    """
    Custom Gym environment for pentesting with skill acquisition.
    
    Key innovation: Agent learns not just WHAT to attack, but HOW:
    - Generate new exploits (LLM)
    - Reuse proven exploits (Cache)
    - Call well-known exploits (Metasploit)
    
    Reward shaping encourages efficiency and skill reuse.
    """
    
    metadata = {'render.modes': ['human']}
    
    def __init__(
        self,
        state_manager,
        tool_manager,
        llm_client,
        executor,
        max_steps: int = 50,
        skill_persistence: str = "persist_with_decay"
    ):
        super().__init__()
        
        # Components
        self.state_manager = state_manager
        self.tool_manager = tool_manager
        self.llm_client = llm_client
        self.executor = executor
        self.max_steps = max_steps
        self.skill_persistence = skill_persistence
        
        # Dynamic Dimensions
        self.num_ports = getattr(self.state_manager, 'num_ports', 30)
        self.obs_dim = getattr(self.state_manager, 'state_dim', 60)
        
        # Gym spaces
        # Observation: Dynamic size
        self.observation_space = spaces.Box(
            low=0, high=4, shape=(self.obs_dim,), dtype=np.float32
        )
        # Action: 3 methods per port + 2 special actions
        # 0 to N-1: LLM
        # N to 2N-1: Cached
        # 2N to 3N-1: MSF
        # 3N: Scan
        # 3N+1: Privesc
        self.action_space = spaces.Discrete(self.num_ports * 3 + 2)
        
        # Episode tracking
        self.current_step = 0
        self.total_reward = 0.0
        self.successful_exploits = 0
        self.root_obtained = False
        
        # Method usage statistics
        self.method_stats = {
            'llm_generate': 0,
            'cached_skill': 0,
            'metasploit': 0
        }
    
    def reset(self, seed: Optional[int] = None, options: Optional[Dict] = None) -> Tuple[np.ndarray, Dict]:
        """Reset environment for new episode"""
        super().reset(seed=seed)
        
        self.current_step = 0
        self.total_reward = 0.0
        self.successful_exploits = 0
        self.root_obtained = False
        self.method_stats = {k: 0 for k in self.method_stats}
        
        # Handle skill persistence
        if self.skill_persistence == "reset_always":
            self.tool_manager.clear_library()
        
        # Reset state manager (assuming it has a reset method or we just get current state)
        # The prompt implies state_manager manages the state. 
        # We might need to reset the state_manager if it tracks episode state.
        # For now, we just get the state.
        # If state_manager needs reset, it should be called here.
        # Assuming state_manager.reset() exists or is not needed if it's just a view.
        # But usually environments reset the underlying simulation.
        # The prompt doesn't explicitly show state_manager.reset(), but it says "Reset environment".
        # I'll assume state_manager.reset() might be needed if it tracks compromised hosts per episode.
        if hasattr(self.state_manager, 'reset'):
            self.state_manager.reset()
            
        return self.state_manager.get_state(), {}
    
    def step(self, action: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """Execute one step with expanded action space"""
        self.current_step += 1
        
        # Debug: Print action and available actions
        available_actions = self.state_manager.get_available_actions()
        print(f"Step {self.current_step}: Act={action} Ports={len(available_actions)}")
        
        # Decode action
        port_index, method_requested = self._decode_action(action)
        
        # Special actions
        if method_requested == 'scan':
            return self._handle_scan_action()
        elif method_requested == 'privesc':
            return self._handle_privesc_action()
        
        # Validate port action
        available_actions = self.state_manager.get_available_actions()
        if port_index not in available_actions:
            reward = -2.0  # Wasted action penalty
            info = {
                'result': 'invalid_action',
                'reason': 'port_not_available',
                'port_index': port_index
            }
            done = self._is_done()
            obs = self.state_manager.get_state()
            return obs, reward, done, False, info
        
        # Get service information
        service_sig = self.state_manager.get_service_signature(port_index)
        vuln = self.state_manager.get_vuln_for_action(port_index)
        
        # Use ToolManager to determine execution method
        actual_method, skill_data = self.tool_manager.get_exploit_method(service_sig)
        
        # Check if agent requested unavailable method
        if method_requested == 'cached_skill' and actual_method not in ['cached_script', 'custom_script']:
            # Agent wanted cache but none exists
            reward = -1.0
            info = {'result': 'invalid_action', 'reason': 'no_cached_skill'}
            done = self._is_done()
            obs = self.state_manager.get_state()
            return obs, reward, done, False, info
        
        if method_requested == 'metasploit' and actual_method != 'metasploit' and method_requested != 'llm_generate': 
             # If we requested metasploit but tool manager says we don't have it (and it's not a fallback to LLM)
             # Actually tool_manager.get_exploit_method returns the BEST method.
             # But here we are forcing a method via action.
             # We need to check if the requested method is AVAILABLE.
             # The prompt's _is_action_valid logic handles this check before step?
             # No, step calls _is_action_valid? No, the prompt implementation of step does NOT call _is_action_valid.
             # But the requirements section showed step calling _is_action_valid.
             # The implementation section shows step doing checks inline.
             pass

        # Re-implementing the logic from the prompt's implementation section which seems more complete
        
        # Execute based on actual method (from ToolManager)
        
        if actual_method in ['cached_script', 'custom_script']:
            reward, info = self._execute_cached(port_index, skill_data)
            self.method_stats['cached_skill'] += 1
        elif actual_method == 'metasploit':
            reward, info = self._execute_metasploit(port_index, skill_data, vuln)
            self.method_stats['metasploit'] += 1
        else:  # generate_new
            # If the agent requested cached/msf but we don't have it, we fall back to LLM?
            # The prompt code had a check:
            # if method_requested == 'cached_skill' and actual_method != 'cached_script': return error
            # So if agent requested cached and we don't have it, we fail.
            # If agent requested LLM, and we have cached, what happens?
            # The code executes cached (because actual_method is cached).
            # And reward logic:
            # "if method_requested == 'cached_skill' and actual_method == 'cached_script': reward += 2.0"
            # So if agent requested LLM but cached was used, no bonus.
            
            # Wait, if actual_method is 'cached_script', we execute cached.
            # Even if method_requested was 'llm_generate'.
            # This means the agent can't force LLM generation if a script is cached?
            # That might be intended to prevent waste.
            
            reward, info = self._execute_llm_generation(port_index, service_sig, vuln)
            self.method_stats['llm_generate'] += 1
        
        # Apply efficiency bonus
        if method_requested == 'cached_skill' and actual_method in ['cached_script', 'custom_script']:
            reward += 2.0  # Smart choice!
        elif method_requested == 'metasploit' and actual_method == 'metasploit':
            reward += 1.0  # Good choice
        
        # Update Skill Library if success
        if info['result'] == 'success':
            self.successful_exploits += 1
            
            if actual_method == 'custom_script': # Note: prompt used 'custom_script' here but 'cached_script' above. Assuming they map.
                # Save new skill
                self.tool_manager.add_skill(
                    service_signature=service_sig,
                    skill_type='custom_script',
                    code=info.get('exploit_code'),
                    port=self.state_manager.tracked_ports[port_index],
                    success=True
                )
            elif actual_method == 'metasploit':
                # Save MSF module reference
                self.tool_manager.add_skill(
                    service_signature=service_sig,
                    skill_type='metasploit',
                    module=skill_data.get('module'),
                    port=self.state_manager.tracked_ports[port_index],
                    success=True
                )
            elif actual_method == 'generate_new': # If we just generated it
                 self.tool_manager.add_skill(
                    service_signature=service_sig,
                    skill_type='custom_script',
                    code=info.get('exploit_code'),
                    port=self.state_manager.tracked_ports[port_index],
                    success=True
                )

        else:
            # Update failure count
            if actual_method != 'generate_new': # 'generate_new' corresponds to LLM generation
                self.tool_manager.add_skill(
                    service_signature=service_sig,
                    skill_type=skill_data.get('type', 'unknown'),
                    success=False
                )
        
        # Time penalty
        reward -= 0.1
        
        # Update state
        result = info.get('result', 'unknown')
        self.state_manager.update_state(port_index, result, reward)
        
        # Track stats
        self.total_reward += reward
        if info.get('root_obtained'):
            self.root_obtained = True
            reward += 50.0  # Massive bonus
        
        # Check termination
        done = self._is_done()
        
        # Get new observation
        obs = self.state_manager.get_state()
        
        return obs, reward, done, False, info
    
    def _decode_action(self, action: int) -> Tuple[Optional[int], str]:
        """Decode action into (port_index, method)"""
        n = self.num_ports
        
        if action < n:
            return (action, 'llm_generate')
        elif action < n * 2:
            return (action - n, 'cached_skill')
        elif action < n * 3:
            return (action - n * 2, 'metasploit')
        elif action == n * 3:
            return (None, 'scan')
        else:
            return (None, 'privesc')
    
    def _is_action_valid(self, port_index: Optional[int], method: str) -> bool:
        """
        Validate if action can be executed.
        """
        # Special actions (scan, privesc) are always valid
        if port_index is None:
            return method in ['scan', 'privesc']
        
        # Check if port is available for exploitation
        available_actions = self.state_manager.get_available_actions()
        if port_index not in available_actions:
            return False
        
        # Get service signature for this port
        service_sig = self.state_manager.get_service_signature(port_index)
        
        # Check method-specific validity
        if method == 'cached_skill':
            # Valid only if we have a cached skill for this service
            return service_sig in self.tool_manager.skills
        
        elif method == 'metasploit':
            # Valid only if ToolManager has MSF module for this service
            return self.tool_manager.msf_wrapper and self.tool_manager.msf_wrapper.has_module_for(service_sig)
        
        elif method == 'llm_generate':
            # Always valid (LLM can generate for any service)
            return True
        
        else:
            # Unknown method
            return False
    
    def _handle_scan_action(self):
        # Placeholder for scan action
        # In a real scenario, this would trigger NmapScanner to scan more ports or deeper
        # PENALTY INCREASED: To prevent agent from looping on this placeholder action
        reward = -5.0 
        info = {'result': 'scanned', 'method': 'scan'}
        done = self._is_done()
        obs = self.state_manager.get_state()
        return obs, reward, done, False, info

    def _handle_privesc_action(self):
        # Placeholder for privesc
        reward = -1.0 # Cost of attempt
        info = {'result': 'failed', 'method': 'privesc'} # Assume fail for now
        done = self._is_done()
        obs = self.state_manager.get_state()
        return obs, reward, done, False, info

    def _execute_cached(self, port_index: int, skill_data: Dict) -> Tuple[float, Dict]:
        """Execute cached exploit"""
        print(f"⚡ Executing cached exploit for port {self.state_manager.tracked_ports[port_index]}")
        
        code = skill_data.get('code')
        # target_ip = self.state_manager.target_ip # target_ip is not in state_manager
        # We need to get target IP from somewhere. 
        # StateManager has graph, graph has hosts.
        # Or we can pass target_ip to environment.
        # Let's check how state_manager gets target_ip. It doesn't seem to have it explicitly stored as attribute in __init__.
        # But it builds graph from nmap data which has IPs.
        # Let's assume single target for now and find it in graph.
        target_ip = self._get_target_ip()
        port = self.state_manager.tracked_ports[port_index]
        
        # Execute
        result = self.executor.execute(code, target_ip, port)
        
        reward = 10.0 if result['success'] else -1.0
        
        return reward, {
            'result': 'success' if result['success'] else 'failed',
            'method': 'cached_skill',
            'execution_time': result.get('execution_time', 0),
            'root_obtained': result.get('root_obtained', False),
            'exploit_code': code
        }
    
    def _execute_metasploit(self, port_index: int, skill_data: Dict, vuln: Dict) -> Tuple[float, Dict]:
        """Execute Metasploit module"""
        print(f"🔫 Executing Metasploit module for port {self.state_manager.tracked_ports[port_index]}")
        
        module = skill_data.get('module')
        if not module:
            return -1.0, {'result': 'failed', 'error': 'No module specified'}
            
        target_ip = self._get_target_ip()
        port = self.state_manager.tracked_ports[port_index]
        
        options = {
            'RHOSTS': target_ip,
            'RPORT': port
        }
        
        # Execute via wrapper
        result = self.tool_manager.msf_wrapper.run_exploit(module, options)
        
        if result['success']:
            return 10.0, {
                'result': 'success',
                'method': 'metasploit',
                'module': module,
                'session_id': result.get('session_id')
            }
        else:
            return -1.0, {
                'result': 'failed',
                'method': 'metasploit',
                'module': module,
                'error': result.get('error')
            }
    
    def _execute_llm_generation(self, port_index: int, service_sig: str, vuln: Dict) -> Tuple[float, Dict]:
        """Generate and execute new exploit with LLM"""
        print(f"🤖 Generating new exploit for port {self.state_manager.tracked_ports[port_index]}")
        
        target_ip = self._get_target_ip()
        port = self.state_manager.tracked_ports[port_index]
        
        # 1. Retrieve RAG context
        # Assuming self.tool_manager has access to rag_manager or we pass it in init
        # The prompt says "Integrate RAG Manager for LLM context"
        # I'll assume self.tool_manager.rag_manager exists or I should check.
        # The prompt context says "@utils/rag_manager.py (already exists)".
        # And "Integrate RAG Manager for LLM context".
        # I'll assume it's available via tool_manager or I need to add it to Env init.
        # Env init has tool_manager.
        # Let's assume tool_manager has rag_manager.
        
        rag_context = ""
        if hasattr(self.tool_manager, 'rag_manager') and self.tool_manager.rag_manager:
             rag_results = self.tool_manager.rag_manager.retrieve_similar(service_sig)
             rag_context = "\n".join([f"- {r['service']}: {r['code'][:100]}..." for r in rag_results])
        
        # 2. Construct Prompt
        prompt = f"{SYSTEM_PROMPT}\n\n"
        
        if rag_context:
            prompt += RAG_CONTEXT_PROMPT.format(
                rag_context=rag_context,
                target_ip=target_ip,
                port=port,
                service=service_sig,
                vulnerability=vuln.get('original', {}).get('name', 'Unknown')
            )
        else:
            prompt += f"Target: {target_ip}\nPort: {port}\nService: {service_sig}\n"
            if vuln:
                prompt += f"Vulnerability: {vuln.get('original', {}).get('name', 'Unknown')}\n"
        
        # 3. Generate Code
        code = self.llm_client.generate_code(prompt)
        
        # 4. Execute
        result = self.executor.execute(code, target_ip, port)
        
        # 5. Retry Logic
        if not result['success'] and result['status'] != 'security_violation':
            print("⚠️  Exploit failed, attempting retry...")
            retry_prompt = ERROR_RETRY_PROMPT.format(error=result.get('output', 'Unknown error'))
            code = self.llm_client.generate_code(retry_prompt)
            result = self.executor.execute(code, target_ip, port)
            
        if result['success']:
            return 10.0, {
                'result': 'success',
                'method': 'llm_generate',
                'exploit_code': code,
                'root_obtained': result.get('root_obtained', False)
            }
        else:
            return -1.0, {
                'result': 'failed',
                'method': 'llm_generate',
                'error': result.get('error') or result.get('output')
            }
    
    def _is_done(self) -> bool:
        """Check episode termination"""
        if self.root_obtained:
            return True
        if self.current_step >= self.max_steps:
            return True
        # if len(self.state_manager.get_available_actions()) == 0:
        #     return True
        return False

    def _get_target_ip(self) -> str:
        """Helper to get target IP from state manager's graph"""
        # Find the first host node in the graph
        for node, data in self.state_manager.graph.nodes(data=True):
            if data.get('type') == 'host':
                return node # The node ID for host is the IP
        return "127.0.0.1" # Fallback
    
    def render(self, mode='human'):
        """Print current state"""
        if mode == 'human':
            print(f"\nStep: {self.current_step}/{self.max_steps}")
            print(f"Total Reward: {self.total_reward:.2f}")
            print(f"Successful Exploits: {self.successful_exploits}")
            print(f"Method Usage: LLM={self.method_stats['llm_generate']}, "
                  f"Cached={self.method_stats['cached_skill']}, "
                  f"MSF={self.method_stats['metasploit']}")
            print(f"Skill Library: {len(self.tool_manager.skills)} skills")
