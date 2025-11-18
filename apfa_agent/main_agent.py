import logging
import yaml
import argparse
from pathlib import Path
from apfa_agent.config.safety import is_running_in_vm, validate_target_ip

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config(config_path: str) -> dict:
    """Loads the agent configuration from a YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="APFA Autonomous Pentesting Agent")
    parser.add_argument("--config", default="apfa_agent/config/agent_config.yaml", help="Path to configuration file")
    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config(args.config)
        logger.info("Configuration loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return

    # Safety Checks
    logger.info("Performing safety checks...")
    
    # 1. VM Check
    if config['safety']['require_vm']:
        if not is_running_in_vm():
            logger.warning("WARNING: Not running in a VM/Container! This is dangerous.")
            # In a real scenario, we might want to exit here, but for now we just warn
            # or follow the config strictness.
            # sys.exit(1) 
        else:
            logger.info("VM/Container environment detected. Proceeding.")

    # 2. Target Validation
    target_ip = config['target']['ip']
    allowed_targets = config['safety']['allowed_targets']
    try:
        validate_target_ip(target_ip, allowed_targets)
        logger.info(f"Target IP {target_ip} is whitelisted.")
    except Exception as e:
        logger.error(str(e))
        return

    logger.info("Agent initialization complete. (Stub)")
    # TODO: Initialize PPO Agent
    # TODO: Initialize LLM Client
    # TODO: Start Main Loop

if __name__ == "__main__":
    main()
