import os
import re
import sys
import logging
from typing import List, Optional

# Configure logging
logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Exception raised for security violations."""
    pass

def is_running_in_vm() -> bool:
    """
    Detects if the agent is running inside a Virtual Machine or Container.
    Checks multiple indicators including Docker files, CPU info, and product names.
    
    Returns:
        bool: True if running in a VM/Container, False otherwise.
    """
    # Check for Docker/Container indicators
    if os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv'):
        return True
    
    # Check cgroup for docker/lxc
    try:
        if os.path.exists('/proc/1/cgroup'):
            with open('/proc/1/cgroup', 'r') as f:
                if 'docker' in f.read() or 'lxc' in f.read():
                    return True
    except Exception:
        pass

    # Check for common VM vendors in product_name
    try:
        if os.path.exists('/sys/class/dmi/id/product_name'):
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                product_name = f.read().lower()
                vm_vendors = ['virtualbox', 'vmware', 'qemu', 'kvm', 'xen', 'bochs', 'innotek']
                if any(vendor in product_name for vendor in vm_vendors):
                    return True
    except Exception:
        pass
        
    # Check for common VM vendors in sys_vendor
    try:
        if os.path.exists('/sys/class/dmi/id/sys_vendor'):
            with open('/sys/class/dmi/id/sys_vendor', 'r') as f:
                sys_vendor = f.read().lower()
                if 'qemu' in sys_vendor:
                    return True
    except Exception:
        pass

    # Fallback: Check cpuinfo for hypervisor
    try:
        with open('/proc/cpuinfo', 'r') as f:
            cpuinfo = f.read().lower()
            if 'hypervisor' in cpuinfo:
                return True
    except Exception:
        pass

    return False

def validate_target_ip(ip_address: str, allowed_targets: List[str]) -> bool:
    """
    Validates if the target IP is in the allowed whitelist.
    
    Args:
        ip_address (str): The IP address to check.
        allowed_targets (List[str]): List of allowed IP addresses.
        
    Returns:
        bool: True if allowed.
        
    Raises:
        SecurityError: If the IP is not allowed.
    """
    if ip_address not in allowed_targets:
        msg = f"Security Violation: Target IP {ip_address} is not in the allowed whitelist: {allowed_targets}"
        logger.error(msg)
        raise SecurityError(msg)
    return True

def sanitize_code(code: str, forbidden_commands: Optional[List[str]] = None) -> str:
    """
    Scans LLM-generated code for dangerous patterns and forbidden commands.
    
    Args:
        code (str): The Python code to sanitize.
        forbidden_commands (List[str], optional): List of specific forbidden command strings.
        
    Returns:
        str: The original code if it passes safety checks.
        
    Raises:
        SecurityError: If dangerous code is detected.
    """
    if forbidden_commands is None:
        # Default forbidden commands if not provided
        forbidden_commands = [
            "rm -rf", "format", "del /f", "dd if=", "mkfs", "> /dev/sda", 
            ":(){ :|:& };:", "wget", "curl", "nc -e"
        ]

    # Normalize code for checking (lowercase)
    code_lower = code.lower()

    # 1. Check for specific forbidden string patterns
    for cmd in forbidden_commands:
        if cmd.lower() in code_lower:
            msg = f"Security Violation: Forbidden command pattern detected: '{cmd}'"
            logger.error(msg)
            raise SecurityError(msg)

    # 2. Regex checks for more complex dangerous patterns
    
    # Detect attempts to delete root or recursive delete
    if re.search(r'rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/', code_lower):
        raise SecurityError("Security Violation: Recursive deletion of root detected.")
        
    # Detect attempts to format disks
    if re.search(r'mkfs\.[a-z]+\s+/dev/', code_lower):
        raise SecurityError("Security Violation: Disk formatting command detected.")

    # Detect fork bombs
    if re.search(r':\(\)\{\s*:\|:&?\s*\};:', code_lower):
        raise SecurityError("Security Violation: Fork bomb detected.")

    # Detect dangerous os.system or subprocess calls with shell=True and dangerous keywords
    # This is a heuristic and not perfect, but catches obvious attempts
    dangerous_keywords = ['rm', 'mkfs', 'dd', 'shutdown', 'reboot', 'wget', 'curl']
    
    # Check for os.system usage with dangerous keywords
    if 'os.system' in code:
        for keyword in dangerous_keywords:
            # Simple check if keyword appears in the same line as os.system
            # A more robust parser would be better but this is a first line of defense
            lines = code.split('\n')
            for line in lines:
                if 'os.system' in line and keyword in line.lower():
                     raise SecurityError(f"Security Violation: Dangerous keyword '{keyword}' found in os.system call.")

    # Check for subprocess usage with dangerous keywords
    if 'subprocess' in code:
         for keyword in dangerous_keywords:
            lines = code.split('\n')
            for line in lines:
                if 'subprocess' in line and keyword in line.lower():
                     raise SecurityError(f"Security Violation: Dangerous keyword '{keyword}' found in subprocess call.")

    return code
