"""
LLM Tool Calling Framework

Provides tools the LLM can call during exploit generation to:
1. Search Metasploit modules
2. Query CVE databases (NVD)
3. Search Exploit-DB
4. Fetch exploit code from public sources

This dramatically improves exploit generation by giving the LLM
access to real-world data instead of hallucinating exploits.
"""

import json
import logging
import os
import subprocess
import requests
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


# ============================================================================
# TOOL 1: Metasploit Module Search
# ============================================================================

def search_msf_modules(
    service: str,
    version: str = "",
    port: Optional[int] = None,
    cve: Optional[str] = None,
    msf_wrapper = None
) -> List[Dict[str, Any]]:
    """
    Search Metasploit's module database for matching exploits.
    
    Args:
        service: Service name (e.g., "vsftpd", "samba")
        version: Service version (e.g., "2.3.4")
        port: Port number (e.g., 21)
        cve: CVE identifier (e.g., "CVE-2011-2523")
        msf_wrapper: MSF wrapper instance (optional)
    
    Returns:
        List of matching modules with metadata
    """
    logger.info(f"[TOOL] search_msf_modules(service={service}, version={version}, port={port}, cve={cve})")
    
    results = []
    
    # Method 1: Use MSF wrapper if available
    if msf_wrapper:
        try:
            # Try to get module info directly
            sig = f"{service} {version}".strip()
            module_info = msf_wrapper.get_module_info(sig)
            
            if module_info:
                results.append({
                    "module": module_info.get("module"),
                    "name": sig,
                    "source": module_info.get("source", "manual"),
                    "reliability": module_info.get("reliability", "unknown"),
                    "payload": module_info.get("payload"),
                    "ports": module_info.get("ports", [port] if port else [])
                })
        except Exception as e:
            logger.error(f"MSF wrapper search failed: {e}")
    
    # Method 2: Use msfconsole command-line search
    try:
        search_term = f"{service} {version}".strip()
        cmd = ["msfconsole", "-q", "-x", f"search {search_term}; exit"]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # Parse msfconsole output
            lines = result.stdout.split('\n')
            for line in lines:
                if 'exploit/' in line or 'auxiliary/' in line:
                    parts = line.split()
                    if parts:
                        results.append({
                            "module": parts[0],
                            "name": ' '.join(parts[1:]) if len(parts) > 1 else parts[0],
                            "source": "msfconsole_search",
                            "search_term": search_term
                        })
    except Exception as e:
        logger.error(f"msfconsole search failed: {e}")
    
    logger.info(f"[TOOL] Found {len(results)} MSF modules")
    return results


# ============================================================================
# TOOL 2: CVE Database Query (NVD API 2.0)
# ============================================================================

class NVDClient:
    """
    Client for NIST National Vulnerability Database API 2.0
    
    Rate limits:
    - Without API key: 5 requests / 30 seconds
    - With API key: 50 requests / 30 seconds
    
    Get free API key at: https://nvd.nist.gov/developers/request-an-api-key
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.last_request = None
        self.rate_limit_delay = 0.6 if self.api_key else 6.0  # seconds
    
    def _rate_limit(self):
        """Implement rate limiting"""
        if self.last_request:
            elapsed = (datetime.now() - self.last_request).total_seconds()
            if elapsed < self.rate_limit_delay:
                import time
                time.sleep(self.rate_limit_delay - elapsed)
        self.last_request = datetime.now()
    
    def query_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Query NVD for CVE details.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2011-2523")
        
        Returns:
            Structured CVE information or None if not found
        """
        logger.info(f"[TOOL] query_cve_database(cve_id={cve_id})")
        
        try:
            self._rate_limit()
            
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            params = {"cveId": cve_id}
            
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("totalResults", 0) > 0:
                    vuln = data["vulnerabilities"][0]["cve"]
                    
                    # Extract CVSS scores
                    cvss_v3 = None
                    cvss_v2 = None
                    
                    metrics = vuln.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    
                    if "cvssMetricV2" in metrics:
                        cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    
                    # Extract references
                    references = [
                        ref.get("url") 
                        for ref in vuln.get("references", [])
                    ]
                    
                    # Extract CWE
                    cwe_list = []
                    for weakness in vuln.get("weaknesses", []):
                        for desc in weakness.get("description", []):
                            cwe_list.append(desc.get("value"))
                    
                    result = {
                        "cve_id": cve_id,
                        "description": vuln.get("descriptions", [{}])[0].get("value", ""),
                        "cvss_v3": cvss_v3,
                        "cvss_v2": cvss_v2,
                        "severity": metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
                        "published": vuln.get("published", ""),
                        "last_modified": vuln.get("lastModified", ""),
                        "references": references[:5],  # Limit to 5 refs
                        "cwe": cwe_list,
                        "source": "nvd_api"
                    }
                    
                    logger.info(f"[TOOL] CVE found: CVSS={cvss_v3 or cvss_v2}, Severity={result['severity']}")
                    return result
            
            elif response.status_code == 403:
                logger.warning("[TOOL] NVD API rate limit hit. Get API key at: https://nvd.nist.gov/developers/request-an-api-key")
            
        except Exception as e:
            logger.error(f"[TOOL] NVD query failed: {e}")
        
        return None


# ============================================================================
# TOOL 3: Exploit-DB Search
# ============================================================================

def search_exploit_db(
    service: Optional[str] = None,
    cve: Optional[str] = None,
    platform: str = "linux"
) -> List[Dict[str, Any]]:
    """
    Search Exploit-DB for public exploits using searchsploit.
    
    Args:
        service: Service name to search for
        cve: CVE identifier to search for
        platform: Platform filter (linux, windows, etc.)
    
    Returns:
        List of matching exploits
    """
    query = service or cve or ""
    logger.info(f"[TOOL] search_exploit_db(query={query}, platform={platform})")
    
    results = []
    
    try:
        # Method 1: searchsploit (if available)
        cmd = ["searchsploit", "-j", query]  # -j = JSON output
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            data = json.loads(result.stdout)
            
            for exploit in data.get("RESULTS_EXPLOIT", []):
                # Filter by platform
                if platform.lower() in exploit.get("Platform", "").lower():
                    results.append({
                        "edb_id": exploit.get("EDB-ID"),
                        "title": exploit.get("Title"),
                        "date": exploit.get("Date"),
                        "author": exploit.get("Author"),
                        "type": exploit.get("Type"),
                        "platform": exploit.get("Platform"),
                        "path": exploit.get("Path"),
                        "url": f"https://www.exploit-db.com/exploits/{exploit.get('EDB-ID')}",
                        "source": "searchsploit"
                    })
        
        logger.info(f"[TOOL] Found {len(results)} exploits in Exploit-DB")
        
    except FileNotFoundError:
        logger.warning("[TOOL] searchsploit not found. Install with: sudo apt install exploitdb")
    except Exception as e:
        logger.error(f"[TOOL] Exploit-DB search failed: {e}")
    
    return results


# ============================================================================
# TOOL 4: Get Exploit Code
# ============================================================================

def get_exploit_code(edb_id: str) -> Optional[str]:
    """
    Download exploit code from Exploit-DB.
    
    Args:
        edb_id: Exploit-DB ID (e.g., "17491")
    
    Returns:
        Raw exploit code or None
    """
    logger.info(f"[TOOL] get_exploit_code(edb_id={edb_id})")
    
    try:
        # Method 1: searchsploit -m (mirror/download)
        cmd = ["searchsploit", "-m", edb_id]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            # searchsploit downloads to current directory
            # Find the downloaded file
            import glob
            files = glob.glob(f"{edb_id}.*")
            
            if files:
                with open(files[0], 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                # Clean up downloaded file
                os.remove(files[0])
                
                logger.info(f"[TOOL] Downloaded exploit code ({len(code)} bytes)")
                return code
        
        # Method 2: Direct download from raw.githubusercontent.com
        url = f"https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/{edb_id}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            logger.info(f"[TOOL] Downloaded exploit code from GitLab ({len(response.text)} bytes)")
            return response.text
        
    except Exception as e:
        logger.error(f"[TOOL] Failed to download exploit: {e}")
    
    return None


# ============================================================================
# Tool Definitions for LLM Function Calling
# ============================================================================

# Define tools in OpenAI function calling format
TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "search_msf_modules",
            "description": "Search Metasploit's exploit database for modules matching a service/vulnerability. Returns professional exploit modules with reliability ratings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Service name (e.g., 'vsftpd', 'samba', 'unrealircd')"
                    },
                    "version": {
                        "type": "string",
                        "description": "Service version (e.g., '2.3.4', '3.0.20')"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number (e.g., 21, 139, 445)"
                    },
                    "cve": {
                        "type": "string",
                        "description": "CVE identifier (e.g., 'CVE-2011-2523')"
                    }
                },
                "required": ["service"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_cve_database",
            "description": "Query NIST National Vulnerability Database for detailed CVE information including CVSS scores, severity, references, and CWE mappings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE identifier (e.g., 'CVE-2011-2523', 'CVE-2007-2447')"
                    }
                },
                "required": ["cve_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_exploit_db",
            "description": "Search Exploit-DB for public proof-of-concept exploits and advisories. Returns exploit code references and metadata.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "Service name to search for"
                    },
                    "cve": {
                        "type": "string",
                        "description": "CVE identifier to search for"
                    },
                    "platform": {
                        "type": "string",
                        "description": "Platform filter (linux, windows, multiple, etc.)",
                        "default": "linux"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_exploit_code",
            "description": "Download actual exploit code from Exploit-DB by EDB-ID. Use this after searching to get the full exploit source code.",
            "parameters": {
                "type": "object",
                "properties": {
                    "edb_id": {
                        "type": "string",
                        "description": "Exploit-DB ID (e.g., '17491')"
                    }
                },
                "required": ["edb_id"]
            }
        }
    }
]


# Tool execution dispatcher
def execute_tool(tool_name: str, arguments: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Any:
    """
    Execute a tool by name with given arguments.
    
    Args:
        tool_name: Name of the tool function
        arguments: Dictionary of arguments
        context: Optional context (e.g., msf_wrapper instance)
    
    Returns:
        Tool execution result
    """
    context = context or {}
    
    if tool_name == "search_msf_modules":
        return search_msf_modules(
            service=arguments.get("service", ""),
            version=arguments.get("version", ""),
            port=arguments.get("port"),
            cve=arguments.get("cve"),
            msf_wrapper=context.get("msf_wrapper")
        )
    
    elif tool_name == "query_cve_database":
        nvd_client = context.get("nvd_client") or NVDClient()
        return nvd_client.query_cve(arguments["cve_id"])
    
    elif tool_name == "search_exploit_db":
        return search_exploit_db(
            service=arguments.get("service"),
            cve=arguments.get("cve"),
            platform=arguments.get("platform", "linux")
        )
    
    elif tool_name == "get_exploit_code":
        return get_exploit_code(arguments["edb_id"])
    
    else:
        raise ValueError(f"Unknown tool: {tool_name}")
