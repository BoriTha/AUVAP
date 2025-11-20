import unittest
import networkx as nx
import numpy as np
import os
import json
from apfa_agent.core.state_manager import StateManager, DEFAULT_TRACKED_PORTS as TRACKED_PORTS, STATE_OPEN, STATE_UNKNOWN

class TestStateManager(unittest.TestCase):
    def setUp(self):
        # Create a dummy graph
        self.graph = nx.DiGraph()
        self.graph.add_node('192.168.1.10', type='host', os='Linux 2.6')
        
        # Add some services
        # Port 80 (in TRACKED_PORTS)
        self.graph.add_node('192.168.1.10:80', type='service', port=80, state='open', product='Apache', version='2.4.41')
        self.graph.add_edge('192.168.1.10', '192.168.1.10:80')
        
        # Port 22 (in TRACKED_PORTS)
        self.graph.add_node('192.168.1.10:22', type='service', port=22, state='open', product='OpenSSH', version='8.2p1')
        self.graph.add_edge('192.168.1.10', '192.168.1.10:22')
        
        # Port 9999 (NOT in TRACKED_PORTS)
        self.graph.add_node('192.168.1.10:9999', type='service', port=9999, state='open')
        self.graph.add_edge('192.168.1.10', '192.168.1.10:9999')

        # Create dummy APFA data
        self.apfa_data = {
            'vulnerabilities': [
                {'port': 80, 'severity': 'high', 'cvss_score': 7.5},
                {'port': 22, 'severity': 'low', 'cvss_score': 2.1}
            ]
        }
        self.apfa_path = 'temp_apfa_test.json'
        with open(self.apfa_path, 'w') as f:
            json.dump(self.apfa_data, f)

    def tearDown(self):
        if os.path.exists(self.apfa_path):
            os.remove(self.apfa_path)

    def test_initialization(self):
        sm = StateManager(self.graph, self.apfa_path)
        state = sm.get_state()
        
        self.assertEqual(state.shape, (60,))
        
        # Check Port 80 (index 5 in TRACKED_PORTS)
        idx_80 = TRACKED_PORTS.index(80)
        self.assertEqual(state[idx_80], STATE_OPEN)
        
        # Check Port 22 (index 1)
        idx_22 = TRACKED_PORTS.index(22)
        self.assertEqual(state[idx_22], STATE_OPEN)
        
        # Check Port 21 (index 0, not in graph)
        idx_21 = TRACKED_PORTS.index(21)
        self.assertEqual(state[idx_21], STATE_UNKNOWN)
        
        # Check OS (Linux)
        self.assertEqual(state[31], 1.0) # Linux
        self.assertEqual(state[30], 0.0) # Windows

    def test_apfa_enrichment(self):
        sm = StateManager(self.graph, self.apfa_path)
        state = sm.get_state()
        
        # Avg CVSS: (7.5 + 2.1) / 2 = 4.8 -> normalized 0.48
        self.assertAlmostEqual(state[32], 0.48)
        
        # High priority count: 1 -> normalized 0.1
        self.assertAlmostEqual(state[33], 0.1)

    def test_service_signature(self):
        sm = StateManager(self.graph, self.apfa_path)
        
        idx_80 = TRACKED_PORTS.index(80)
        sig = sm.get_service_signature(idx_80)
        self.assertEqual(sig, "apache 2.4.41")

    def test_update_state(self):
        sm = StateManager(self.graph, self.apfa_path)
        idx_80 = TRACKED_PORTS.index(80)
        
        sm.update_state(idx_80, 'success', 10.0)
        
        state = sm.get_state()
        self.assertEqual(state[idx_80], 4) # STATE_COMPROMISED
        
        stats = sm.get_statistics()
        self.assertEqual(stats['successes'], 1)
        self.assertEqual(stats['total_reward'], 10.0)

if __name__ == '__main__':
    unittest.main()
