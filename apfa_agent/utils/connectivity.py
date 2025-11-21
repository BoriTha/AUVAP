"""
Connectivity checking utilities for target hosts.
"""
import socket
import subprocess
import logging
import time
from typing import Optional, Tuple, Dict

logger = logging.getLogger(__name__)

# Global cache for connectivity results
# Structure: {ip: {'status': bool, 'message': str, 'timestamp': float, 'ports': {port: (bool, str)}}}
_connectivity_cache: Dict[str, Dict] = {}
_cache_ttl = 300  # Cache results for 5 minutes (300 seconds)


def clear_connectivity_cache(ip: Optional[str] = None):
    """
    Clear the connectivity cache.
    
    Args:
        ip (str, optional): If provided, only clear cache for this IP. 
                           If None, clear entire cache.
    """
    global _connectivity_cache
    if ip:
        if ip in _connectivity_cache:
            del _connectivity_cache[ip]
            logger.debug(f"Cleared connectivity cache for {ip}")
    else:
        _connectivity_cache.clear()
        logger.debug("Cleared entire connectivity cache")


def _is_cache_valid(ip: str) -> bool:
    """Check if cached result for IP is still valid."""
    if ip not in _connectivity_cache:
        return False
    
    cached_time = _connectivity_cache[ip].get('timestamp', 0)
    age = time.time() - cached_time
    
    return age < _cache_ttl


def check_host_connectivity(ip: str, port: Optional[int] = None, timeout: int = 5, use_cache: bool = True) -> Tuple[bool, str]:
    """
    Check if a target host is reachable.
    
    Args:
        ip (str): Target IP address
        port (int, optional): Specific port to check. If None, uses ICMP ping
        timeout (int): Timeout in seconds for connectivity check
        use_cache (bool): Whether to use cached results (default: True)
        
    Returns:
        Tuple[bool, str]: (is_reachable, message)
    """
    # Check cache first
    if use_cache and _is_cache_valid(ip):
        cache_entry = _connectivity_cache[ip]
        
        # If no port specified, return host-level status
        if port is None:
            logger.debug(f"Using cached connectivity result for {ip}")
            return cache_entry['status'], cache_entry['message']
        
        # OPTIMIZATION: If host is known to be completely unreachable (ping failed),
        # don't bother checking individual ports - they'll all fail
        if not cache_entry['status']:
            logger.debug(f"Host {ip} is cached as unreachable, skipping port {port} check")
            return False, f"Host {ip} is not reachable (no ICMP response) (cached)"
        
        # If port specified, check if we have cached port result
        if port in cache_entry.get('ports', {}):
            port_status, port_msg = cache_entry['ports'][port]
            logger.debug(f"Using cached connectivity result for {ip}:{port}")
            if port_status:
                return True, f"Host {ip}:{port} is reachable (cached)"
            else:
                return False, f"Host {ip} is reachable but port {port} is not open: {port_msg} (cached)"
    
    # Check if we need to do a fresh ping or can reuse cached host status
    need_ping = True
    ping_reachable = False
    
    if use_cache and ip in _connectivity_cache and _is_cache_valid(ip):
        # We have cached host status, reuse it for new port checks
        ping_reachable = _connectivity_cache[ip]['status']
        need_ping = False
        logger.debug(f"Reusing cached host status for {ip} (checking new port {port})")
    else:
        # Need to perform actual ping check
        logger.debug(f"Performing connectivity check for {ip}" + (f":{port}" if port else ""))
        ping_reachable = _ping_host(ip, timeout)
    
    # Initialize or update cache entry
    if ip not in _connectivity_cache:
        _connectivity_cache[ip] = {
            'status': ping_reachable,
            'message': '',
            'timestamp': time.time(),
            'ports': {}
        }
    elif need_ping:
        # Only update timestamp if we did a fresh check
        _connectivity_cache[ip]['timestamp'] = time.time()
        _connectivity_cache[ip]['status'] = ping_reachable
    
    if not ping_reachable:
        logger.warning(f"Host {ip} is not responding to ICMP ping")
        _connectivity_cache[ip]['message'] = f"Host {ip} is not reachable (no ICMP response)"
        
        # If ping fails but port is specified, still try port check
        # (some hosts block ICMP but have services running)
        if port:
            logger.info(f"Attempting TCP connection to {ip}:{port} despite ping failure")
        else:
            return False, _connectivity_cache[ip]['message']
    else:
        _connectivity_cache[ip]['message'] = f"Host {ip} is reachable (ICMP response received)"
    
    # If port is specified, check TCP connectivity
    if port:
        port_reachable, port_msg = _check_port(ip, port, timeout)
        
        # Cache the port result
        _connectivity_cache[ip]['ports'][port] = (port_reachable, port_msg)
        
        if port_reachable:
            return True, f"Host {ip}:{port} is reachable"
        else:
            return False, f"Host {ip} is reachable but port {port} is not open: {port_msg}"
    
    # If only ping was requested and it succeeded
    return True, _connectivity_cache[ip]['message']


def _ping_host(ip: str, timeout: int = 5) -> bool:
    """
    Ping a host using ICMP.
    
    Args:
        ip (str): Target IP address
        timeout (int): Timeout in seconds
        
    Returns:
        bool: True if host responds to ping, False otherwise
    """
    try:
        # Use platform-appropriate ping command
        # -c 1: send 1 packet
        # -W timeout: wait timeout seconds for response
        result = subprocess.run(
            ['ping', '-c', '1', '-W', str(timeout), ip],
            capture_output=True,
            timeout=timeout + 1  # Add buffer to subprocess timeout
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.debug(f"Ping to {ip} timed out")
        return False
    except Exception as e:
        logger.debug(f"Ping to {ip} failed with error: {e}")
        return False


def _check_port(ip: str, port: int, timeout: int = 5) -> Tuple[bool, str]:
    """
    Check if a specific TCP port is open and accepting connections.
    
    Args:
        ip (str): Target IP address
        port (int): Target port
        timeout (int): Connection timeout in seconds
        
    Returns:
        Tuple[bool, str]: (is_open, message)
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            return True, "Port is open"
        else:
            return False, f"Port is closed or filtered (error code: {result})"
            
    except socket.timeout:
        return False, "Connection timed out"
    except socket.gaierror:
        return False, "Hostname could not be resolved"
    except socket.error as e:
        return False, f"Socket error: {e}"
    except Exception as e:
        return False, f"Unexpected error: {e}"
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def check_multiple_ports(ip: str, ports: list, timeout: int = 5) -> dict:
    """
    Check connectivity to multiple ports on a host.
    
    Args:
        ip (str): Target IP address
        ports (list): List of ports to check
        timeout (int): Timeout per port check
        
    Returns:
        dict: Dictionary mapping port numbers to (reachable, message) tuples
    """
    results = {}
    
    # First check if host is reachable at all
    host_reachable, _ = check_host_connectivity(ip, port=None, timeout=timeout)
    
    if not host_reachable:
        logger.warning(f"Host {ip} is not reachable, skipping port checks")
        for port in ports:
            results[port] = (False, "Host unreachable")
        return results
    
    # Check each port
    for port in ports:
        is_open, msg = _check_port(ip, port, timeout)
        results[port] = (is_open, msg)
        
    return results


def verify_target_before_attack(ip: str, port: int, timeout: int = 5, use_cache: bool = True) -> Tuple[bool, str]:
    """
    Comprehensive connectivity check before launching an attack.
    Logs results and provides actionable feedback.
    Uses caching to avoid redundant checks for the same IP.
    
    Args:
        ip (str): Target IP address
        port (int): Target port
        timeout (int): Timeout in seconds
        use_cache (bool): Whether to use cached results (default: True)
        
    Returns:
        Tuple[bool, str]: (should_proceed, reason)
    """
    # Check if we have a cached result
    cache_status = "(cached)" if (use_cache and _is_cache_valid(ip)) else ""
    logger.info(f"Verifying connectivity to target {ip}:{port}... {cache_status}")
    
    try:
        is_reachable, message = check_host_connectivity(ip, port, timeout, use_cache=use_cache)
        
        if is_reachable:
            logger.info(f"✓ Target {ip}:{port} is reachable and ready for attack {cache_status}")
            return True, message
        else:
            logger.warning(f"✗ Target {ip}:{port} is not reachable: {message}")
            return False, message
            
    except Exception as e:
        logger.error(f"Connectivity check failed with error: {e}")
        return False, f"Connectivity check error: {e}"


def get_connectivity_cache_stats() -> Dict:
    """
    Get statistics about the connectivity cache.
    
    Returns:
        Dict: Cache statistics including number of IPs, ports checked, etc.
    """
    total_ports = sum(len(entry.get('ports', {})) for entry in _connectivity_cache.values())
    valid_cache_entries = sum(1 for ip in _connectivity_cache.keys() if _is_cache_valid(ip))
    
    return {
        'total_ips': len(_connectivity_cache),
        'valid_entries': valid_cache_entries,
        'total_ports_checked': total_ports,
        'cache_ttl_seconds': _cache_ttl,
        'cached_ips': list(_connectivity_cache.keys())
    }
