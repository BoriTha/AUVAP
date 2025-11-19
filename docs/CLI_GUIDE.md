# DeepExploit Hybrid - Unified CLI Guide

The `apfa_cli.py` is the central command-line interface for the DeepExploit Hybrid penetration testing system. It orchestrates all components—network scanning, vulnerability parsing, classification, and autonomous exploitation—into a single, cohesive tool.

## 🚀 Getting Started

### Prerequisites
Ensure you have installed the project dependencies:
```bash
pip install -r requirements.txt
```

### Basic Usage
Make the script executable (optional but recommended):
```bash
chmod +x apfa_cli.py
```

Run the help command to see available options:
```bash
./apfa_cli.py --help
```

---

## 🛠️ Commands

### 1. Setup
Interactive configuration wizard. Use this to set your default target IP and learn about API key configuration.

```bash
./apfa_cli.py setup
```
*Note: This updates `apfa_agent/config/agent_config.yaml`.*

### 2. Scan
Runs an Nmap scan against a target.

```bash
./apfa_cli.py scan --target 192.168.1.10
```
*   **--target**: IP address to scan (overrides config).
*   **--output**: (Optional) Path to save raw Nmap output.

### 3. Classify
The bridge between scanning and exploitation. Parses scan results (Nessus/JSON), applies filters, and enriches data for the LLM.

**Basic Classification:**
```bash
./apfa_cli.py classify my_scan.nessus --output classified_vulns.json
```

**Using Filters:**
You can filter vulnerabilities by port, CVSS score, or specific keywords using a YAML config file.

Generate a filter template:
```bash
./apfa_cli.py classify --init-config
```

Apply the filter:
```bash
./apfa_cli.py classify input.nessus --config filters.yaml
```

### 4. Attack
Launches the autonomous agent.

**Modes:**
*   `llm-only`: (Default) Uses LLM logic for decision making (Smart Triage).
*   `hybrid`: Combines PPO (Reinforcement Learning) with LLM guidance.
*   `train`: Runs the RL training loop.
*   `eval`: Evaluates the trained model.

**Examples:**
```bash
# Standard Smart Triage Attack
./apfa_cli.py attack --target 192.168.1.10 --mode llm-only

# Attack using pre-classified vulnerabilities (Recommended)
./apfa_cli.py attack --target 192.168.1.10 --mode hybrid --input-file classified_vulns.json
```

### 5. Workflow
Predefined automation chains for common tasks.

**Full Workflow (Scan -> Attack):**
```bash
./apfa_cli.py workflow full --target 192.168.1.10
```

**Ingest Workflow (Nessus -> Classify):**
```bash
./apfa_cli.py workflow ingest --nessus-file raw_scan.nessus
```

---

## 💡 Helper Script
The `run_pentest.sh` script has been updated to wrap the CLI for convenience.

```bash
./run_pentest.sh --target 192.168.1.50 --mode hybrid
```

## 🔍 Global Flags
*   **--dry-run**: Preview what the command will do without executing actions.
    ```bash
    ./apfa_cli.py attack --target 1.2.3.4 --dry-run
    ```
