import numpy as np
import networkx as nx
import json
import logging
import os
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Constants
TRACKED_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 3306, 3389,
    5432, 5900, 6667, 8080, 8443, 8888, 9200, 27017,
    6000, 6001, 9090
]

STATE_UNKNOWN = 0      # Port not scanned
STATE_OPEN = 1         # Port is open
STATE_TRIED = 2        # Exploit attempted (outcome unknown)
STATE_FAILED = 3       # Exploit failed
STATE_COMPROMISED = 4  # Exploit succeeded

class StateManager:
    def __init__(self, graph: nx.DiGraph, apfa_data_path: Optional[str] = None):
        """
        Initialize the StateManager.
        
        Args:
            graph: The NetworkX graph from TerrainMapper.
            apfa_data_path: Path to the APFA classified vulnerabilities JSON.
        """
        self.graph = graph
        self.apfa_data = self._load_apfa_data(apfa_data_path)
        self.state_vector = np.zeros(60, dtype=np.float32)
        
        # Mappings
        self.port_to_vuln = {} # Map port -> vulnerability details
        self.action_history = [] # List of (action_id, result, reward)
        
        # Statistics
        self.stats = {
            'total_attempts': 0,
            'successes': 0,
            'failures': 0,
            'total_reward': 0.0
        }
        
        self._init_state_vector()
        self._enrich_with_apfa()

    def _load_apfa_data(self, path: Optional[str]) -> Dict[str, Any]:
        """Load APFA classified data if available."""
        if not path or not os.path.exists(path):
            logger.warning(f"APFA data not found at {path}. Proceeding without vulnerability enrichment.")
            return {}
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                logger.info(f"Loaded APFA data from {path}")
                return data
        except Exception as e:
            logger.error(f"Failed to load APFA data: {e}")
            return {}

    def _init_state_vector(self):
        """Initialize the state vector based on the graph."""
        # Reset vector
        self.state_vector.fill(0)
        
        # 1. Port Status [0-29]
        # Iterate through tracked ports and check if they are open in the graph
        # We need to find service nodes in the graph
        
        # Create a map of open ports from the graph
        open_ports = set()
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'service' and data.get('state') == 'open':
                try:
                    port = int(data.get('port'))
                    open_ports.add(port)
                except (ValueError, TypeError):
                    continue
        
        for i, port in enumerate(TRACKED_PORTS):
            if port in open_ports:
                self.state_vector[i] = STATE_OPEN
            else:
                self.state_vector[i] = STATE_UNKNOWN # Or should it be closed? 
                                                     # Requirement says 0=unknown. 
                                                     # If not in graph, it's effectively unknown or closed.
                                                     # Keeping as unknown (0) is safe.

        # 2. OS Detection [30-31]
        # Find host node
        windows_conf = 0.0
        linux_conf = 0.0
        
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'host':
                os_str = str(data.get('os', '')).lower()
                if 'windows' in os_str:
                    windows_conf = 1.0 # Simple binary for now, could be confidence score if Nmap provides
                if 'linux' in os_str:
                    linux_conf = 1.0
                # If we have multiple hosts, this might be ambiguous, but assuming single target for now
                # or taking the first host found.
                break 
        
        self.state_vector[30] = windows_conf
        self.state_vector[31] = linux_conf

        # 3. APFA Metrics [32-33] (Placeholder, populated in _enrich_with_apfa)
        
        # 4. Reserved [34-59] -> Already 0

    def _enrich_with_apfa(self):
        """Enrich state with APFA vulnerability data."""
        if not self.apfa_data:
            return

        # This assumes apfa_data structure matches what's expected.
        # Usually it's a list of vulnerabilities or a dict with 'vulnerabilities' key.
        # Let's assume it's the 'classified_output.json' structure.
        
        vulns = self.apfa_data.get('vulnerabilities', [])
        if not vulns and isinstance(self.apfa_data, list):
             vulns = self.apfa_data

        total_cvss = 0.0
        high_priority_count = 0
        count = 0

        for vuln in vulns:
            port = vuln.get('port')
            if port:
                try:
                    port = int(port)
                    self.port_to_vuln[port] = vuln
                except ValueError:
                    pass
            
            # CVSS
            cvss = vuln.get('cvss_score', 0.0)
            if cvss:
                total_cvss += float(cvss)
                count += 1
            
            # Priority
            severity = vuln.get('severity', '').lower()
            if severity in ['high', 'critical']:
                high_priority_count += 1

        # Update State Vector
        if count > 0:
            avg_cvss = total_cvss / count
            self.state_vector[32] = avg_cvss / 10.0 # Normalize 0-1
        
        # Normalize high priority count (arbitrary cap at 10 for normalization)
        self.state_vector[33] = min(high_priority_count / 10.0, 1.0)

    def get_state(self) -> np.ndarray:
        """Return a copy of the current state vector."""
        return self.state_vector.copy()

    def get_state_hash(self) -> str:
        """Return a hash of the state for Q-table indexing."""
        return str(hash(self.state_vector.tobytes()))

    def get_available_actions(self) -> List[int]:
        """
        Return list of valid action indices (indices into TRACKED_PORTS).
        An action is valid if the port is OPEN or TRIED (retry?).
        Usually we want to attack OPEN ports.
        """
        actions = []
        for i, port in enumerate(TRACKED_PORTS):
            status = self.state_vector[i]
            # Allow attacking OPEN ports. 
            # Maybe allow retrying FAILED? For now, just OPEN.
            # Also, if we have APFA data, we might prioritize those, but RL should learn that.
            if status == STATE_OPEN:
                actions.append(i)
        return actions

    def get_vuln_for_action(self, action_id: int) -> Optional[Dict[str, Any]]:
        """Get vulnerability details for a specific action (port index)."""
        if 0 <= action_id < len(TRACKED_PORTS):
            port = TRACKED_PORTS[action_id]
            return self.port_to_vuln.get(port)
        return None

    def update_state(self, action_id: int, result: str, reward: float):
        """
        Update state after an exploitation attempt.
        
        Args:
            action_id: The index of the port attacked.
            result: 'success' or 'failure'.
            reward: The reward received.
        """
        if not (0 <= action_id < len(TRACKED_PORTS)):
            logger.error(f"Invalid action_id: {action_id}")
            return

        # Update Statistics
        self.stats['total_attempts'] += 1
        self.stats['total_reward'] += reward
        self.action_history.append((action_id, result, reward))

        # Update State Vector
        if result == 'success':
            self.state_vector[action_id] = STATE_COMPROMISED
            self.stats['successes'] += 1
        else:
            self.state_vector[action_id] = STATE_FAILED # Or STATE_TRIED if we want to distinguish
            self.stats['failures'] += 1

        # Update Graph (Optional but good for consistency)
        # We need to find the node for this port
        port = TRACKED_PORTS[action_id]
        # This is tricky because we need the IP. Assuming single host or finding the node.
        # We'll search for the service node with this port.
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'service' and int(data.get('port', -1)) == port:
                if result == 'success':
                    self.graph.nodes[node]['state'] = 'compromised'
                # else: maybe mark as 'tried'

    def get_service_signature(self, action_id: int) -> str:
        """
        Get the service signature (product + version) for the target port.
        Used by ToolManager to find exploits.
        """
        if not (0 <= action_id < len(TRACKED_PORTS)):
            return "unknown"

        port = TRACKED_PORTS[action_id]
        
        # Find the service node in the graph
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'service':
                try:
                    node_port = int(data.get('port', -1))
                    if node_port == port:
                        product = data.get('product', '')
                        version = data.get('version', '')
                        service = data.get('service', '')
                        
                        # Construct signature
                        if product and version:
                            return f"{product} {version}".lower()
                        elif product:
                            return product.lower()
                        elif service:
                            return service.lower()
                        else:
                            return "unknown"
                except (ValueError, TypeError):
                    continue
        
        return "unknown"

    def get_statistics(self) -> Dict[str, Any]:
        """Return exploitation statistics."""
        return self.stats.copy()

    def get_compromised_ports(self) -> List[int]:
        """Return list of successfully exploited ports."""
        compromised = []
        for i, status in enumerate(self.state_vector[:30]):
            if status == STATE_COMPROMISED:
                compromised.append(TRACKED_PORTS[i])
        return compromised

    def print_state(self):
        """Print a human-readable summary of the state."""
        print("\n=== State Vector Summary ===")
        print(f"Open Ports: {[TRACKED_PORTS[i] for i, s in enumerate(self.state_vector[:30]) if s == STATE_OPEN]}")
        print(f"Compromised: {[TRACKED_PORTS[i] for i, s in enumerate(self.state_vector[:30]) if s == STATE_COMPROMISED]}")
        print(f"Failed: {[TRACKED_PORTS[i] for i, s in enumerate(self.state_vector[:30]) if s == STATE_FAILED]}")
        print(f"OS Confidence: Win={self.state_vector[30]:.2f}, Linux={self.state_vector[31]:.2f}")
        print(f"Avg CVSS: {self.state_vector[32]*10:.2f}")
        print(f"High Priority Vulns (norm): {self.state_vector[33]:.2f}")
        print("============================")
