import numpy as np
import networkx as nx
import json
import logging
import os
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Constants - Default ports to track if no scan data available
DEFAULT_TRACKED_PORTS = [
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
    def __init__(self, graph: nx.DiGraph, apfa_data_path: Optional[str] = None, tracked_ports: Optional[List[int]] = None):
        """
        Initialize the StateManager.
        
        Args:
            graph: The NetworkX graph from TerrainMapper.
            apfa_data_path: Path to the APFA classified vulnerabilities JSON.
            tracked_ports: Optional list of specific ports to track (overrides dynamic discovery).
        """
        self.graph = graph
        self.apfa_data = self._load_apfa_data(apfa_data_path)
        
        # Dynamic Port Discovery: Extract all open ports from the graph
        if tracked_ports is not None:
            # User-specified scope (e.g., for focused pentesting)
            self.tracked_ports = tracked_ports
            logger.info(f"Using scoped ports: {self.tracked_ports}")
        else:
            # Auto-discover from scan results
            discovered_ports = self._discover_open_ports()
            if discovered_ports:
                self.tracked_ports = sorted(discovered_ports)
                logger.info(f"Dynamically tracking {len(self.tracked_ports)} discovered ports: {self.tracked_ports}")
            else:
                # Fallback to default list
                self.tracked_ports = DEFAULT_TRACKED_PORTS
                logger.warning(f"No ports discovered in scan, using default list of {len(self.tracked_ports)} ports")
        
        self.num_ports = len(self.tracked_ports)
        
        # State Vector Sizing
        # [Ports (N)] + [OS (2)] + [APFA (2)] + [Reserved (4)]
        self.metadata_offset = self.num_ports
        self.state_dim = self.num_ports + 8
        self.state_vector = np.zeros(self.state_dim, dtype=np.float32)
        
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

    def _discover_open_ports(self) -> List[int]:
        """Discover all open ports from the graph."""
        open_ports = set()
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'service' and data.get('state') == 'open':
                try:
                    port = int(data.get('port'))
                    open_ports.add(port)
                except (ValueError, TypeError):
                    continue
        return list(open_ports)

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
        
        # 1. Port Status [0 to N-1]
        # Create a map of open ports from the graph
        open_ports = set()
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'service' and data.get('state') == 'open':
                try:
                    port = int(data.get('port'))
                    open_ports.add(port)
                except (ValueError, TypeError):
                    continue
        
        # Debug: Print open ports found in graph
        print(f"DEBUG: StateManager found open ports in graph: {open_ports}")
        print(f"DEBUG: Tracked ports: {self.tracked_ports}")
        
        for i, port in enumerate(self.tracked_ports):
            if port in open_ports:
                self.state_vector[i] = STATE_OPEN
            else:
                self.state_vector[i] = STATE_UNKNOWN

        # 2. OS Detection [N, N+1]
        # Find host node
        windows_conf = 0.0
        linux_conf = 0.0
        
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'host':
                os_str = str(data.get('os', '')).lower()
                if 'windows' in os_str:
                    windows_conf = 1.0
                if 'linux' in os_str:
                    linux_conf = 1.0
                break 
        
        self.state_vector[self.metadata_offset] = windows_conf
        self.state_vector[self.metadata_offset + 1] = linux_conf

        # 3. APFA Metrics [N+2, N+3] (Placeholder, populated in _enrich_with_apfa)
        
        # 4. Reserved [N+4 to End] -> Already 0

    def _enrich_with_apfa(self):
        """Enrich state with APFA vulnerability data."""
        if not self.apfa_data:
            return
        
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

        # Update State Vector (after OS)
        if count > 0:
            avg_cvss = total_cvss / count
            self.state_vector[self.metadata_offset + 2] = avg_cvss / 10.0 # Normalize 0-1
        
        # Normalize high priority count
        self.state_vector[self.metadata_offset + 3] = min(high_priority_count / 10.0, 1.0)

    def get_state(self) -> np.ndarray:
        """Return a copy of the current state vector."""
        return self.state_vector.copy()

    def get_state_hash(self) -> str:
        """Return a hash of the state for Q-table indexing."""
        return str(hash(self.state_vector.tobytes()))

    def get_available_actions(self) -> List[int]:
        """
        Return list of valid action indices (indices into tracked_ports).
        An action is valid if the port is OPEN or TRIED (retry?).
        Usually we want to attack OPEN ports.
        """
        actions = []
        for i, port in enumerate(self.tracked_ports):
            status = self.state_vector[i]
            # Allow attacking OPEN ports. 
            # Also allow retrying FAILED ports (maybe with different method)
            if status == STATE_OPEN or status == STATE_FAILED:
                actions.append(i)
        return actions

    def get_vuln_for_action(self, action_id: int) -> Optional[Dict[str, Any]]:
        """Get vulnerability details for a specific action (port index)."""
        if 0 <= action_id < len(self.tracked_ports):
            port = self.tracked_ports[action_id]
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
        if not (0 <= action_id < len(self.tracked_ports)):
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
            self.state_vector[action_id] = STATE_FAILED
            self.stats['failures'] += 1

        # Update Graph (Optional but good for consistency)
        port = self.tracked_ports[action_id]
        for node, data in self.graph.nodes(data=True):
            if data.get('type') == 'service' and int(data.get('port', -1)) == port:
                if result == 'success':
                    self.graph.nodes[node]['state'] = 'compromised'

    def get_service_signature(self, action_id: int) -> str:
        """
        Get the service signature (product + version) for the target port.
        Used by ToolManager to find exploits.
        """
        if not (0 <= action_id < len(self.tracked_ports)):
            return "unknown"

        port = self.tracked_ports[action_id]
        
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
        # Add compromised ports list to stats
        self.stats['compromised_ports'] = self.get_compromised_ports()
        return self.stats.copy()

    def get_compromised_ports(self) -> List[int]:
        """Return list of successfully exploited ports."""
        compromised = []
        for i, status in enumerate(self.state_vector[:self.num_ports]):
            if status == STATE_COMPROMISED:
                compromised.append(self.tracked_ports[i])
        return compromised

    def print_state(self):
        """Print a human-readable summary of the state."""
        print("\n=== State Vector Summary ===")
        print(f"Open Ports: {[self.tracked_ports[i] for i, s in enumerate(self.state_vector[:self.num_ports]) if s == STATE_OPEN]}")
        print(f"Compromised: {[self.tracked_ports[i] for i, s in enumerate(self.state_vector[:self.num_ports]) if s == STATE_COMPROMISED]}")
        print(f"Failed: {[self.tracked_ports[i] for i, s in enumerate(self.state_vector[:self.num_ports]) if s == STATE_FAILED]}")
        print(f"OS Confidence: Win={self.state_vector[self.metadata_offset]:.2f}, Linux={self.state_vector[self.metadata_offset+1]:.2f}")
        print(f"Avg CVSS: {self.state_vector[self.metadata_offset+2]*10:.2f}")
        print(f"High Priority Vulns (norm): {self.state_vector[self.metadata_offset+3]:.2f}")
        print("============================")
