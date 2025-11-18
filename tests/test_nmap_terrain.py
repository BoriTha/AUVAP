import unittest
import os
import sys
import yaml
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from apfa_agent.core.nmap_scanner import NmapScanner
from apfa_agent.core.terrain_mapper import TerrainMapper

class TestNmapTerrain(unittest.TestCase):
    def setUp(self):
        self.config = {
            'scanning': {
                'mode': 'auto',
                'live_scan': {
                    'output_dir': 'data/scans_test',
                    'cache_duration': 3600
                },
                'sudo': False
            }
        }
        
    def test_scanner_init(self):
        scanner = NmapScanner(self.config)
        self.assertIsNotNone(scanner)
        self.assertEqual(scanner.mode, 'auto')
        
    def test_terrain_mapper_init(self):
        mapper = TerrainMapper()
        self.assertIsNotNone(mapper)
        
    def test_graph_build(self):
        mapper = TerrainMapper()
        dummy_data = {
            'hosts': [
                {
                    'ip': '192.168.1.1',
                    'status': 'up',
                    'os': 'Linux',
                    'services': [
                        {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http'}
                    ]
                }
            ]
        }
        graph = mapper.build_graph(dummy_data)
        self.assertEqual(len(graph.nodes), 2) # 1 host + 1 service
        self.assertTrue(graph.has_edge('192.168.1.1', '192.168.1.1:80'))

if __name__ == '__main__':
    unittest.main()
