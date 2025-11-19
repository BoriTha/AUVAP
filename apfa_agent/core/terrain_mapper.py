import networkx as nx
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class TerrainMapper:
    def __init__(self):
        """Initialize the TerrainMapper."""
        self.graph = nx.DiGraph()

    def build_graph(self, nmap_data: Dict[str, Any]) -> nx.DiGraph:
        """
        Build a NetworkX graph from Nmap scan results.
        
        Args:
            nmap_data: The dictionary returned by NmapScanner.scan()
            
        Returns:
            A NetworkX DirectedGraph representing the network terrain.
        """
        self.graph.clear()
        
        hosts = nmap_data.get('hosts', [])
        logger.info(f"Building terrain graph for {len(hosts)} hosts.")
        
        for host in hosts:
            ip = host.get('ip')
            if not ip:
                continue
                
            # Add Host Node
            self.graph.add_node(
                ip,
                type='host',
                status=host.get('status', 'unknown'),
                os=host.get('os', 'unknown'),
                hostname=host.get('hostname', '') # hostname might not be in my parser yet, but good to have
            )
            
            # Add Service Nodes and Edges
            services = host.get('services', [])
            for svc in services:
                port = svc.get('port')
                protocol = svc.get('protocol', 'tcp')
                state = svc.get('state', 'unknown')
                
                        # Unique ID for service node: IP:PORT
                service_node_id = f"{ip}:{port}"
                
                # Debug: Print service being added
                print(f"DEBUG: TerrainMapper adding service {service_node_id} - state: {state}, service: {svc.get('service', 'unknown')}")
                
                self.graph.add_node(
                    service_node_id,
                    type='service',
                    port=port,
                    protocol=protocol,
                    state=state,
                    service=svc.get('service', 'unknown'),
                    product=svc.get('product', 'unknown'),
                    version=svc.get('version', 'unknown')
                )
                
                # Edge from Host to Service
                self.graph.add_edge(ip, service_node_id, relation='exposes')
                
        logger.info(f"Graph built with {self.graph.number_of_nodes()} nodes and {self.graph.number_of_edges()} edges.")
        return self.graph

    def get_graph(self) -> nx.DiGraph:
        """Return the current graph."""
        return self.graph
