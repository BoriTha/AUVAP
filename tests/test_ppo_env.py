import unittest
from unittest.mock import MagicMock, Mock
import numpy as np
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from apfa_agent.environment import PentestingEnv

class TestPentestingEnv(unittest.TestCase):
    def setUp(self):
        self.state_manager = MagicMock()
        self.tool_manager = MagicMock()
        self.llm_client = MagicMock()
        self.executor = MagicMock()
        
        # Mock state manager methods
        self.state_manager.get_state.return_value = np.zeros(60, dtype=np.float32)
        self.state_manager.get_available_actions.return_value = [0, 1, 2]
        self.state_manager.get_service_signature.return_value = "vsftpd 2.3.4"
        self.state_manager.get_vuln_for_action.return_value = {'classification': {'priority_score': 10}}
        self.state_manager.TRACKED_PORTS = {0: 21, 1: 22, 2: 80}
        self.state_manager.target_ip = "192.168.1.10"
        
        # Mock tool manager
        self.tool_manager.skills = {}
        self.tool_manager.get_exploit_method.return_value = ('llm_generate', {})
        
        self.env = PentestingEnv(
            state_manager=self.state_manager,
            tool_manager=self.tool_manager,
            llm_client=self.llm_client,
            executor=self.executor
        )

    def test_action_decoding(self):
        """Test action decoding logic"""
        # 0-29: LLM Generate
        self.assertEqual(self.env._decode_action(5), (5, 'llm_generate'))
        # 30-59: Cached Skill
        self.assertEqual(self.env._decode_action(35), (5, 'cached_skill'))
        # 60-89: Metasploit
        self.assertEqual(self.env._decode_action(65), (5, 'metasploit'))
        # 90: Scan
        self.assertEqual(self.env._decode_action(90), (None, 'scan'))
        # 91: Privesc
        self.assertEqual(self.env._decode_action(91), (None, 'privesc'))

    def test_action_space(self):
        """Test action and observation spaces"""
        self.assertEqual(self.env.action_space.n, 92)
        self.assertEqual(self.env.observation_space.shape, (60,))

    def test_skill_library_integration(self):
        """Test skill library updates on success"""
        # Setup
        self.env.reset()
        self.tool_manager.skills = {} # Ensure empty
        
        # Mock successful execution
        self.tool_manager.get_exploit_method.return_value = ('llm_generate', {})
        # We need to mock _execute_llm_generation to return success
        # But it's a private method. We can mock the return value of step indirectly?
        # Or we can just run step and rely on the random seed or mock random?
        
        # Let's mock np.random.random to return 0.0 (success)
        with unittest.mock.patch('numpy.random.random', return_value=0.0):
            obs, reward, done, truncated, info = self.env.step(0)
            
        # Check if add_skill was called
        self.tool_manager.add_skill.assert_called()
        self.assertEqual(info['result'], 'success')

    def test_efficiency_bonuses(self):
        """Test efficiency bonuses"""
        # Setup: Agent requests cached skill, and it IS available
        self.tool_manager.get_exploit_method.return_value = ('cached_script', {'code': 'print("pwned")'})
        self.tool_manager.skills = {"vsftpd 2.3.4": {}} # Make sure validation passes
        
        # Mock executor success
        self.executor.execute_code.return_value = {'success': True}
        
        # Action 30 corresponds to cached_skill for port 0
        obs, reward, done, truncated, info = self.env.step(30)
        
        # Base reward 10.0 + Efficiency 2.0 - Time 0.1 = 11.9
        self.assertAlmostEqual(reward, 11.9)

    def test_skill_persistence_modes(self):
        """Test skill persistence modes"""
        # Reset Always
        env_reset = PentestingEnv(
            self.state_manager, self.tool_manager, self.llm_client, self.executor,
            skill_persistence="reset_always"
        )
        env_reset.reset()
        self.tool_manager.clear_library.assert_called()
        
        # Persist Forever
        self.tool_manager.clear_library.reset_mock()
        env_persist = PentestingEnv(
            self.state_manager, self.tool_manager, self.llm_client, self.executor,
            skill_persistence="persist_forever"
        )
        env_persist.reset()
        self.tool_manager.clear_library.assert_not_called()

if __name__ == '__main__':
    unittest.main()
