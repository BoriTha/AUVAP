import os
import sys
import time
import subprocess
import logging
import paramiko
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from apfa_agent.config.safety import sanitize_code, is_running_in_vm, SecurityError

logger = logging.getLogger(__name__)

class CowboyExecutor:
    """
    Executes generated Python exploit code in a controlled environment.
    Includes safety checks, timeout handling, and post-exploitation.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.temp_dir = Path("data/temp")
        self.evidence_dir = Path("data/agent_results")
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Safety check: Ensure we are in a VM/Container if configured to require it
        if self.config.get('require_vm', True) and not is_running_in_vm():
            logger.warning("⚠️  Agent is NOT running in a VM/Container! Execution might be dangerous.")
            # In a real scenario, we might abort here. For now, just warn.

    def execute(self, code: str, target_ip: str, port: int, timeout: int = 30) -> Dict[str, Any]:
        """
        Executes the provided Python code.
        
        Args:
            code (str): Python code to execute.
            target_ip (str): Target IP address.
            port (int): Target port.
            timeout (int): Execution timeout in seconds.
            
        Returns:
            Dict[str, Any]: Execution results.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exploit_{target_ip}_{port}_{timestamp}.py"
        filepath = self.temp_dir / filename
        
        result = {
            "success": False,
            "status": "failed",
            "output": "",
            "error": "",
            "evidence": None,
            "timestamp": timestamp
        }

        try:
            # 1. Sanitize Code
            try:
                safe_code = sanitize_code(code)
            except SecurityError as e:
                result["error"] = str(e)
                result["status"] = "security_violation"
                return result

            # 2. Write to temp file
            with open(filepath, 'w') as f:
                f.write(safe_code)
            
            # 3. Execute
            logger.info(f"Executing exploit for {target_ip}:{port}...")
            process = subprocess.run(
                [sys.executable, str(filepath)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            stdout = process.stdout
            stderr = process.stderr
            result["output"] = stdout + "\n" + stderr
            
            # 4. Parse Results
            # Check for explicit success marker OR common shell indicators
            success_indicators = ["STATUS: SUCCESS", "uid=0(root)", "gid=0(root)", "# ", "$ "]
            
            if any(indicator in stdout for indicator in success_indicators):
                result["success"] = True
                result["status"] = "success"
                logger.info(f"✓ Exploit succeeded for {target_ip}:{port}")
                
                # 4.5. Extract detailed exploit information
                exploit_details = self._extract_exploit_details(stdout)
                result.update(exploit_details)
                
                # 5. Post-Exploitation (if successful)
                self._handle_post_exploitation(target_ip, port, stdout, result)
                
            elif "STATUS: FAILED" in stdout:
                result["status"] = "failed"
                logger.info(f"✗ Exploit failed for {target_ip}:{port}")
            else:
                result["status"] = "unknown"
                logger.warning(f"? Unknown status for {target_ip}:{port}")

        except subprocess.TimeoutExpired:
            result["error"] = "Execution timed out"
            result["status"] = "timeout"
            logger.error(f"⏱️ Exploit timed out for {target_ip}:{port}")
            
        except Exception as e:
            result["error"] = str(e)
            result["status"] = "error"
            logger.error(f"💥 Execution error: {e}")
            
        finally:
            # 6. Cleanup
            if filepath.exists():
                try:
                    os.remove(filepath)
                except Exception:
                    pass
                    
        return result

    def _extract_exploit_details(self, output: str) -> Dict[str, Any]:
        """
        Extract detailed information from exploit output.
        Looks for patterns like:
        - EXPLOIT: <description>
        - COMMAND: <cmd>
        - CREDENTIALS: <user:pass>
        - ACCESS: <level>
        """
        details = {}
        
        for line in output.splitlines():
            line = line.strip()
            
            if line.startswith("EXPLOIT:"):
                details["exploit_method"] = line.split("EXPLOIT:")[1].strip()
                
            elif line.startswith("COMMAND:"):
                cmd = line.split("COMMAND:")[1].strip()
                if "commands_executed" not in details:
                    details["commands_executed"] = []
                details["commands_executed"].append(cmd)
                
            elif line.startswith("CREDENTIALS:"):
                creds = line.split("CREDENTIALS:")[1].strip()
                details["credentials"] = creds
                
            elif line.startswith("ACCESS:"):
                access = line.split("ACCESS:")[1].strip()
                details["access_level"] = access
                if access.lower() in ["root", "administrator"]:
                    details["root_access"] = True
        
        return details

    def _handle_post_exploitation(self, target_ip: str, port: int, output: str, result: Dict[str, Any]):
        """
        Handles post-exploitation actions like SSH connection and evidence collection.
        """
        # Check if we have credentials in the output
        # This is a simple heuristic. Real implementation would be more robust.
        # Expecting output like: "CREDENTIALS: user:password"
        
        creds = None
        for line in output.splitlines():
            if "CREDENTIALS:" in line:
                parts = line.split("CREDENTIALS:")[1].strip().split(":")
                if len(parts) >= 2:
                    creds = (parts[0], parts[1])
                    break
        
        if creds:
            user, password = creds
            logger.info(f"Attempting SSH post-exploitation with {user}:{password}...")
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target_ip, username=user, password=password, timeout=10)
                
                commands = ["whoami", "id", "uname -a", "pwd", "ls -la /root"]
                evidence_text = f"Target: {target_ip}:{port}\nTimestamp: {result['timestamp']}\n\n"
                
                for cmd in commands:
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    out = stdout.read().decode().strip()
                    evidence_text += f"$ {cmd}\n{out}\n\n"
                    
                    if cmd == "id" and "uid=0" in out:
                        result["root_access"] = True
                        logger.info("🔥 ROOT ACCESS CONFIRMED!")

                ssh.close()
                
                # Save evidence
                evidence_file = self.evidence_dir / f"evidence_{target_ip}_{port}_{result['timestamp']}.txt"
                with open(evidence_file, 'w') as f:
                    f.write(evidence_text)
                
                result["evidence"] = str(evidence_file)
                
            except Exception as e:
                logger.error(f"Post-exploitation failed: {e}")
                result["post_exploit_error"] = str(e)
