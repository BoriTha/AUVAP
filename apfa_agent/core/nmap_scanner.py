import nmap
import xml.etree.ElementTree as ET
import os
import time
import logging
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the NmapScanner with configuration.
        
        Args:
            config: Dictionary containing the 'scanning' configuration section.
        """
        self.config = config.get('scanning', {})
        self.mode = self.config.get('mode', 'auto')
        self.live_scan_config = self.config.get('live_scan', {})
        self.output_dir = self.live_scan_config.get('output_dir', 'data/scans')
        self.sudo = self.config.get('sudo', False)
        
        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize nmap PortScanner
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.warning("nmap not found in path. Live scans will fail.")
            self.nm = None
        except Exception as e:
            logger.error(f"Error initializing nmap: {e}")
            self.nm = None

    def scan(self, target: str) -> Dict[str, Any]:
        """
        Execute the scan based on the configured mode.
        
        Args:
            target: The target IP address or hostname.
            
        Returns:
            Dict containing the parsed scan results.
        """
        logger.info(f"Starting scan for target: {target} in mode: {self.mode}")
        
        if self.mode == 'use_existing':
            xml_path = self.config.get('nmap_xml')
            if not xml_path or not os.path.exists(xml_path):
                logger.error(f"Mode is 'use_existing' but nmap_xml is invalid: {xml_path}")
                # Fallback or raise? Prompt implies we should support this mode.
                # If invalid, maybe try to find a recent one or fail.
                # For now, let's try to find a recent one in output_dir if not specified
                xml_path = self._find_latest_scan(target)
                if not xml_path:
                    raise FileNotFoundError("No existing Nmap XML found.")
            return self._load_existing_scan(xml_path)
            
        elif self.mode == 'live':
            return self._run_live_scan(target)
            
        elif self.mode == 'auto':
            # Check for recent scan
            latest_scan = self._find_latest_scan(target)
            if latest_scan and self._is_recent(latest_scan):
                logger.info(f"Found recent scan: {latest_scan}. Using cached data.")
                return self._load_existing_scan(latest_scan)
            else:
                logger.info("No recent scan found. Running live scan.")
                return self._run_live_scan(target)
        
        else:
            logger.error(f"Unknown scan mode: {self.mode}")
            raise ValueError(f"Unknown scan mode: {self.mode}")

    def _run_live_scan(self, target: str) -> Dict[str, Any]:
        """Run a live Nmap scan."""
        if not self.nm:
            raise RuntimeError("Nmap not initialized. Cannot run live scan.")
            
        args = self.live_scan_config.get('arguments', '-sV -sC --top-ports 1000 -T4')
        
        # Construct command for logging/debugging
        cmd = f"nmap {args} {target}"
        if self.sudo:
            # python-nmap handles sudo if we run the script as sudo, 
            # but if we need to invoke nmap with sudo from a non-root script, 
            # python-nmap might not support it directly without 'sudo' in the command path or arguments.
            # However, standard practice is to run the agent as root if needed.
            # If 'sudo' is true in config, we might assume the user wants us to prepend sudo?
            # python-nmap's scan() method takes 'arguments'.
            # If we are not root, nmap might fail for some scans (e.g. -sS).
            # We'll assume the environment is set up correctly or we are running as root if needed.
            pass

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"nmap_{target}_{timestamp}.xml"
        output_path = os.path.join(self.output_dir, output_filename)
        
        # Add -oX to arguments to save XML
        # python-nmap saves it if we ask, but we can also just let it parse.
        # But requirements say "Save scans to data/scans/..."
        # We can pass arguments to nmap to save the file.
        full_args = f"{args} -oX {output_path}"
        
        logger.info(f"Executing: nmap {full_args} {target}")
        
        try:
            # We use self.nm.scan() which returns a dict, but we also want the XML file.
            # Passing -oX in arguments works with python-nmap.
            self.nm.scan(hosts=target, arguments=full_args, sudo=self.sudo)
            
            # The scan method populates self.nm.csv(), self.nm.all_hosts(), etc.
            # But we also want to parse the XML file we just generated to ensure consistency 
            # with the _load_existing_scan method.
            
            if os.path.exists(output_path):
                return self._load_existing_scan(output_path)
            else:
                # Fallback to parsing the result from python-nmap if file wasn't created
                # (though -oX should create it)
                logger.warning("XML output file not found. Parsing internal nmap result.")
                # This is a bit trickier to unify with XML parsing. 
                # Let's rely on the file being created.
                raise FileNotFoundError(f"Nmap did not create output file: {output_path}")
                
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise

    def _load_existing_scan(self, xml_path: str) -> Dict[str, Any]:
        """Load and parse an existing Nmap XML file."""
        logger.info(f"Loading scan from: {xml_path}")
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            return self._parse_nmap_xml(root)
        except Exception as e:
            logger.error(f"Failed to parse XML {xml_path}: {e}")
            raise

    def _parse_nmap_xml(self, root: ET.Element) -> Dict[str, Any]:
        """
        Parse Nmap XML into a structured format compatible with TerrainMapper.
        
        Returns:
            Dict with structure:
            {
                'hosts': [
                    {
                        'ip': '...',
                        'status': 'up|down',
                        'os': '...',
                        'services': [
                            {
                                'port': 80,
                                'protocol': 'tcp',
                                'state': 'open',
                                'service': 'http',
                                'product': 'Apache',
                                'version': '2.4.41'
                            },
                            ...
                        ]
                    },
                    ...
                ]
            }
        """
        results = {'hosts': []}
        
        for host in root.findall('host'):
            # Get IP
            address = host.find('address')
            if address is None:
                continue
            ip = address.get('addr')
            if not ip:
                continue
                
            # Get Status
            status_elem = host.find('status')
            status = status_elem.get('state') if status_elem is not None else 'unknown'
            
            # Get OS
            os_name = "unknown"
            os_match = host.find('os/osmatch')
            if os_match is not None:
                os_name = os_match.get('name', 'unknown')
            
            host_data = {
                'ip': ip,
                'status': status,
                'os': os_name,
                'services': []
            }
            
            # Get Ports
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    service_elem = port.find('service')
                    service_name = 'unknown'
                    product = 'unknown'
                    version = 'unknown'
                    
                    if service_elem is not None:
                        service_name = service_elem.get('name', 'unknown')
                        product = service_elem.get('product', 'unknown')
                        version = service_elem.get('version', 'unknown')
                    
                    service_data = {
                        'port': int(port_id) if port_id else 0,
                        'protocol': protocol,
                        'state': state,
                        'service': service_name,
                        'product': product,
                        'version': version
                    }
                    host_data['services'].append(service_data)
            
            results['hosts'].append(host_data)
            
        return results

    def _find_latest_scan(self, target: str) -> Optional[str]:
        """Find the most recent scan file for the target."""
        files = os.listdir(self.output_dir)
        target_files = [f for f in files if f.startswith(f"nmap_{target}_") and f.endswith(".xml")]
        
        if not target_files:
            return None
            
        # Sort by timestamp in filename
        target_files.sort(reverse=True)
        return os.path.join(self.output_dir, target_files[0])

    def _is_recent(self, file_path: str) -> bool:
        """Check if the file is younger than cache_duration."""
        cache_duration = self.live_scan_config.get('cache_duration', 3600)
        file_time = os.path.getmtime(file_path)
        current_time = time.time()
        return (current_time - file_time) < cache_duration
