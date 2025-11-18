```xml
<objective>
Map GENERAL network topology/attack graph from Nmap scan or auto-scan of ANY target. Parse Nmap XML → graph (NetworkX), annotate with classified vulns. Output JSON/Mermaid for RL traversal/viz. Test on ms2-scan-result.xml (Metasploitable2 demo). For general auto-pentesting paper/demo.
</objective>

<context>
Builds on 001: classified JSON e.g., data/processed/ms2_classified.json.
General input: Nmap XML or bash nmap -sV -p- -oX TARGET.
Test: @data/input/ms2-scan-result.xml (192.168.79.128).
Use NetworkX, pyvis/Mermaid.
</context>

<requirements>
1. Parse ANY Nmap XML → hosts, ports, services, OS.
2. Load classified vulns → annotate nodes (host:port → vulns, severity, mitre).
3. Build graph:
   - Nodes: host_ip:port (service), vuln metadata.
   - Edges: intra-host chains, inter-host (traceroute/ARP/ping).
   - If no Nmap: Auto !nmap -sV -p- -T4 --top-ports 1000 TARGET_IP -oX temp.xml
4. Attack graph: Paths from 'attacker' (MSF machine IP) to targets, weights=CVSS/exploitability.
5. CLI: python tools/topology.py --nmap-xml PATH --classified-json PATH --target-ip TARGET --output JSON
6. Test: ms2-scan-result.xml → 20+ nodes.
</requirements>

<output>
- tools/topology_mapper.py (CLI)
- data/topology/example_attack_graph.json
- docs/topology/example_diagram.mmd (Mermaid)
- examples/visualize_topology.py (pyvis HTML)
</output>

<verification>
1. Graph from ms2 Nmap: 20+ nodes, vulns annotated.
2. Mermaid valid.
3. JSON NetworkX-loadable.
4. Handles multi-host.
</verification>

<success_criteria>
- General topology/attack graph from any Nmap, ready for RL.
</success_criteria>
```