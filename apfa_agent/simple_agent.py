import os
import yaml
import random
import math
from typing import Tuple, Optional, Dict, Any


class SimpleHeuristicAgent:
    def __init__(self, state_manager, tool_manager, llm_client, executor, config_path: str = "apfa_agent/config/agent_config.yaml"):
        self.state_manager = state_manager
        self.tool_manager = tool_manager
        self.llm_client = llm_client
        self.executor = executor
        self.env = None
        self.model = None
        self.config_path = config_path
        self.config = self._load_config()
        self.stats = {
            'total_episodes': 0,
            'total_steps': 0,
            'total_reward': 0.0,
            'successes': 0,
        }

    def _load_config(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    data = yaml.safe_load(f) or {}
                    return data.get('agent', {}) or {}
        except Exception:
            return {}
        return {}

    def set_environment(self, env):
        self.env = env

    def predict(self, obs, deterministic: bool = True) -> Tuple[int, Optional[object]]:
        n = getattr(self.env, 'num_ports', getattr(self.state_manager, 'num_ports', 30))
        available = self.state_manager.get_available_actions()

        if not available:
            # No available ports: choose scan or privesc
            scan_idx = n * 3
            privesc_idx = n * 3 + 1
            return (scan_idx if random.random() < 0.8 else privesc_idx, None)

        best_score = -math.inf
        best_choice = (0, 'llm_generate')

        for p in available:
            service_sig = self.state_manager.get_service_signature(p)
            vuln = self.state_manager.get_vuln_for_action(p) or {}

            base_score = 0.0
            if isinstance(vuln, dict):
                base_score = float(vuln.get('cvss', 0.0) or vuln.get('classification', {}).get('priority_score', 0.0) or 0.0)

            cached_bonus = 0.0
            if service_sig in self.tool_manager.skills:
                cached_bonus = 5.0

            msf_bonus = 0.0
            if getattr(self.tool_manager, 'msf_wrapper', None) and self.tool_manager.msf_wrapper:
                try:
                    if self.tool_manager.msf_wrapper.has_module_for(service_sig):
                        msf_bonus = 3.0
                except Exception:
                    msf_bonus = 0.0

            failure_penalty = 0.0
            skill = self.tool_manager.skills.get(service_sig, {}) if hasattr(self.tool_manager, 'skills') else {}
            if skill:
                failures = skill.get('fail_count', skill.get('failures', 0))
                failure_penalty = failures * 0.5

            random_epsilon = 0.0 if deterministic else random.random() * 0.5

            # Preference order: cached > msf > llm, encoded via bonus
            score_cached = base_score + cached_bonus - failure_penalty + random_epsilon
            score_msf = base_score + msf_bonus - failure_penalty + random_epsilon
            score_llm = base_score + 0.5 - failure_penalty + random_epsilon

            # Choose best method for this port
            if score_cached >= score_msf and score_cached >= score_llm:
                method, score = 'cached_skill', score_cached
            elif score_msf >= score_cached and score_msf >= score_llm:
                method, score = 'metasploit', score_msf
            else:
                method, score = 'llm_generate', score_llm

            if score > best_score:
                best_score = score
                best_choice = (p, method)

        port_index, method = best_choice
        if method == 'cached_skill':
            action = n + port_index
        elif method == 'metasploit':
            action = 2 * n + port_index
        else:
            action = port_index

        return action, None

    def train(self, total_timesteps: int = 10000) -> Dict[str, Any]:
        if not self.env:
            raise RuntimeError("Environment not set for agent. Call set_environment(env) before training.")

        # Map timesteps to episodes: default 1000 timesteps per episode
        episodes = max(1, int(total_timesteps // 1000))
        if episodes == 0:
            episodes = 1

        results = []
        for ep in range(episodes):
            obs, _ = self.env.reset()
            done = False
            ep_reward = 0.0
            while not done:
                action, _ = self.predict(obs, deterministic=False)
                obs, reward, terminated, truncated, info = self.env.step(action)
                done = terminated or truncated
                ep_reward += reward
                self.stats['total_steps'] += 1
            results.append(ep_reward)
            self.stats['total_episodes'] += 1
            self.stats['total_reward'] += ep_reward
            if info.get('root_obtained'):
                self.stats['successes'] += 1

        avg_reward = sum(results) / len(results) if results else 0.0
        return {'average_reward': avg_reward, 'success_rate': self.stats['successes'] / self.stats['total_episodes'] if self.stats['total_episodes'] else 0.0}

    def evaluate(self, n_episodes: int = 10) -> Dict[str, Any]:
        if not self.env:
            raise RuntimeError("Environment not set for agent. Call set_environment(env) before evaluating.")

        total_rewards = []
        successes = 0
        for i in range(n_episodes):
            obs, _ = self.env.reset()
            done = False
            ep_reward = 0
            while not done:
                action, _ = self.predict(obs, deterministic=True)
                obs, reward, terminated, truncated, info = self.env.step(action)
                done = terminated or truncated
                ep_reward += reward
            total_rewards.append(ep_reward)
            if info.get('root_obtained'):
                successes += 1

        avg_reward = sum(total_rewards) / len(total_rewards) if total_rewards else 0.0
        success_rate = successes / n_episodes if n_episodes else 0.0
        return {
            'average_reward': avg_reward,
            'success_rate': success_rate,
            'episodes': n_episodes
        }

    # Backwards compatibility
    def save_model(self):
        return

    def load(self):
        return

    def initialize_model(self, force_new: bool = False):
        return
