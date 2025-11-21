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
    query: str,
    service: Optional[str] = None,
    version: Optional[str] = None,
    port: Optional[int] = None,
    cve: Optional[str] = None,
    msf_wrapper = None,
    max_results: int = 10
) -> List[Dict[str, Any]]:
    """
    Search Metasploit's module database for matching exploits.
    
    The LLM can search freely with any query string to find relevant modules.
    
    Args:
        query: Free-form search query (e.g., "vsftpd backdoor", "samba usermap", "unreal irc")
        service: Optional service name for context (e.g., "vsftpd", "samba")
        version: Optional version for context (e.g., "2.3.4")
        port: Optional port number for filtering (e.g., 21)
        cve: Optional CVE identifier (e.g., "CVE-2011-2523")
        msf_wrapper: MSF wrapper instance (optional)
        max_results: Maximum number of results to return (default: 10)
    
    Returns:
        List of matching modules with detailed metadata for LLM to choose from
        
    Example LLM usage:
        1. search_msf_modules(query="vsftpd") → Find all vsftpd exploits
        2. search_msf_modules(query="backdoor", service="vsftpd") → Find backdoor exploits for vsftpd
        3. search_msf_modules(query="samba usermap") → Find samba usermap exploit
    """
    logger.info(f"[TOOL] search_msf_modules(query='{query}', service={service}, version={version}, port={port}, cve={cve})")
    
    results = []
    seen_modules = set()
    
    # Method 1: Search via MSF RPC (most comprehensive)
    if msf_wrapper and msf_wrapper.client:
        try:
            # Use service-specific search queries for better results
            if service and service.lower() != "unknown":
                # Create more targeted search queries
                service_queries = [
                    f"{service} {version}" if version else service,
                    f"{service}/",
                    f"{service} exploit",
                    f"{service} vulnerability"
                ]
                search_results = []
                for service_query in service_queries:
                    try:
                        query_results = msf_wrapper.client.modules.search(service_query)
                        search_results.extend(query_results)
                    except:
                        continue
            else:
                # Fallback to original query
                search_results = msf_wrapper.client.modules.search(query)
            
            for module in search_results:
                module_path = module.get('fullname', '')
                
                # Skip if already seen
                if module_path in seen_modules:
                    continue
                seen_modules.add(module_path)
                
                # Filter by type (exploits and auxiliary)
                module_type = 'exploit' if 'exploit/' in module_path else 'auxiliary'
                
                # Service-specific filtering to avoid inappropriate matches
                if service:
                    service_lower = service.lower()
                    module_path_lower = module_path.lower()
                    description_lower = module.get('description', '').lower()
                    
                    # Require module path to contain the service name for better matching
                    # This ensures FTP exploits actually contain "ftp" in their path
                    service_patterns = {
                        'ftp': ['ftp/'],
                        'ssh': ['ssh/'],
                        'smb': ['smb/'],
                        'smtp': ['smtp/'],
                        'telnet': ['telnet/'],
                        'http': ['http/', 'https/'],
                        'https': ['http/', 'https/'],
                        'mysql': ['mysql/'],
                        'postgresql': ['postgresql/', 'postgres/'],
                        'irc': ['irc/'],
                    }
                    
                    # Skip if module path doesn't contain expected service pattern
                    if service_lower in service_patterns:
                        has_service_pattern = any(pattern in module_path_lower 
                                               for pattern in service_patterns[service_lower])
                        if not has_service_pattern:
                            continue
                    
                    # Additional filtering for obviously mismatched services
                    skip_patterns = {
                        'ftp': ['webapp/', 'www'],
                        'ssh': ['webapp/', 'www'],
                        'smb': ['webapp/', 'www'],
                        'smtp': ['webapp/', 'www'],
                        'telnet': ['webapp/', 'www'],
                        'http': ['ftp/', 'ssh/', 'smb/', 'smtp/'],
                        'https': ['ftp/', 'ssh/', 'smb/', 'smtp/'],
                        'mysql': ['webapp/', 'www'],
                        'postgresql': ['webapp/', 'www'],
                        'irc': ['webapp/', 'www'],
                    }
                    
                    # Check if module path contains incompatible service patterns
                    should_skip = False
                    if service_lower in skip_patterns:
                        for bad_pattern in skip_patterns[service_lower]:
                            if bad_pattern in module_path_lower:
                                # Skip this module as it's for a different service
                                should_skip = True
                                break
                    
                    if should_skip:
                        continue
                
                # Get detailed module information
                    try:
                        msf_module = msf_wrapper.client.modules.use(module_type, module_path)
                        
                        # Extract required options and ports
                        required_opts = {}
                        target_ports = []
                        
                        if msf_module and hasattr(msf_module, 'options'):
                            for opt_name, opt_info in msf_module.options.items():
                                if opt_info.get('required'):
                                    required_opts[opt_name] = opt_info.get('default', '')
                                
                                # Extract port from RPORT option
                                if opt_name == 'RPORT':
                                    try:
                                        target_ports.append(int(opt_info.get('default', 0)))
                                    except:
                                        pass
                        
                        # Extract description
                        description = module.get('description', module.get('name', ''))
                        
                        # Determine rank/reliability
                        rank = module.get('rank', 'unknown')
                        rank_scores = {
                            'excellent': 5,
                            'great': 4,
                            'good': 3,
                            'normal': 2,
                            'average': 2,
                            'low': 1,
                            'manual': 1
                        }
                        reliability_score = rank_scores.get(rank.lower(), 0)
                        
                        results.append({
                            "module": module_path,
                            "type": module_type,
                            "name": module.get('name', ''),
                            "description": description[:200],  # Truncate long descriptions
                            "rank": rank,
                            "reliability_score": reliability_score,
                            "disclosure_date": module.get('disclosure_date', ''),
                            "ports": target_ports,
                            "required_options": list(required_opts.keys()),
                            "source": "msf_rpc_search",
                            "search_query": query
                        })
                        
                    except Exception as e:
                        # If can't get details, still add basic info with reliability score
                        rank = module.get('rank', 'normal')
                        rank_scores = {
                            'excellent': 5,
                            'great': 4,
                            'good': 3,
                            'normal': 2,
                            'average': 2,
                            'low': 1,
                            'manual': 1
                        }
                        reliability_score = rank_scores.get(rank.lower(), 2)  # Default to 2 (normal)
                        
                        results.append({
                            "module": module_path,
                            "type": module_type,
                            "name": module.get('name', ''),
                            "description": module.get('description', '')[:200],
                            "rank": rank,
                            "reliability_score": reliability_score,
                            "source": "msf_rpc_search",
                            "search_query": query
                        })
            
            logger.info(f"[TOOL] MSF RPC search found {len(results)} modules")
            
        except Exception as e:
            logger.error(f"MSF RPC search failed: {e}")
    
    # Method 2: Check manual mapping (high-confidence results)
    if msf_wrapper and service:
        try:
            sig = f"{service} {version}".strip() if version else service
            module_info = msf_wrapper.get_module_info(sig)
            
            if module_info:
                module_path = module_info.get("module")
                if module_path and module_path not in seen_modules:
                    seen_modules.add(module_path)
                    results.insert(0, {  # Insert at front (highest priority)
                        "module": module_path,
                        "type": "exploit" if "exploit/" in module_path else "auxiliary",
                        "name": sig,
                        "source": module_info.get("source", "manual"),
                        "reliability": module_info.get("reliability", "unknown"),
                        "reliability_score": 5,  # Manual mappings are highest trust
                        "payload": module_info.get("payload"),
                        "ports": module_info.get("ports", [port] if port else []),
                        "cve": module_info.get("cve"),
                        "search_query": query,
                        "note": "This is a manually curated mapping with verified reliability"
                    })
        except Exception as e:
            logger.error(f"MSF wrapper mapping check failed: {e}")
    
    # Sort by reliability score (highest first)
    results.sort(key=lambda x: x.get('reliability_score', 0), reverse=True)
    
    # Limit results
    results = results[:max_results]
    
    logger.info(f"[TOOL] Returning {len(results)} MSF modules for LLM selection")
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
                        "codes": exploit.get("Codes", ""),  # CVE codes
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
            "description": "Search Metasploit's exploit database with ANY search query. You can search by service name, version, vulnerability type, CVE, or keywords. Returns ranked modules with detailed metadata so you can choose the best one. Try multiple searches with different keywords to find the right exploit.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free-form search query. Examples: 'vsftpd', 'samba usermap', 'backdoor ftp', 'unreal irc', 'distcc', 'proftpd 1.3'. Be creative with keywords!"
                    },
                    "service": {
                        "type": "string",
                        "description": "Optional: Service name for context (e.g., 'vsftpd', 'samba', 'unrealircd')"
                    },
                    "version": {
                        "type": "string",
                        "description": "Optional: Service version for context (e.g., '2.3.4', '3.0.20')"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Optional: Port number for filtering (e.g., 21, 139, 445)"
                    },
                    "cve": {
                        "type": "string",
                        "description": "Optional: CVE identifier (e.g., 'CVE-2011-2523')"
                    }
                },
                "required": ["query"]
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
            query=arguments.get("query", arguments.get("service", "")),  # Allow query or service
            service=arguments.get("service"),
            version=arguments.get("version"),
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
