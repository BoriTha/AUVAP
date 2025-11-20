# APFA LLM Agent

Autonomous pentesting agent powered by Large Language Models for intelligent vulnerability exploitation.

## Architecture

The APFA agent uses a simplified intelligent architecture:

- **Smart Triage**: Prioritizes vulnerabilities based on impact and exploitability
- **LLM-Powered Decision Making**: Uses language models to generate attack strategies
- **Automated Tool Selection**: Chooses appropriate tools (metasploit, nmap, custom exploits)
- **Intelligent Execution**: Executes attacks with proper validation and error handling

## Usage

### Quick Start
```bash
./run_pentest.sh agent <IP>
```

### Manual Execution
```bash
python apfa_agent/main_agent_simplified.py --mode agent --target <IP>
```

### With Existing Nessus Scans
```bash
python scripts/parse_and_classify.py data/input/scan.nessus data/output/result.json
python apfa_agent/main_agent_simplified.py --mode agent --classified-data data/output/result.json
```

## Configuration

Configuration is in `apfa_agent/config/agent_config.yaml`.
Key settings:
- `target`: Default target IP
- `llm`: LLM provider settings (OpenAI, Anthropic, etc.)
- `execution`: Tool execution and safety settings
- `scanning`: Nmap and vulnerability scanning options

## Safety

The agent includes safety checks to ensure it is running in a controlled environment.
- VM detection is enabled by default
- Network isolation is recommended
- To bypass safety checks (NOT RECOMMENDED): `export APFA_SKIP_SAFETY_CHECK=true`

## Components

### Core Modules
- **nmap_scanner.py**: Network discovery and vulnerability scanning
- **llm_client.py**: Universal interface to multiple LLM providers
- **executor.py**: Safe tool execution with validation
- **state_manager.py**: Tracks attack progress and results

### Intelligence Modules
- **llm_ranker.py**: Prioritizes vulnerabilities for exploitation
- **rag_manager.py**: Retrieves relevant exploit knowledge
- **tool_manager.py**: Manages pentesting tools and resources
- **report_generator.py**: Creates detailed pentest reports

### Data Processing
- **nessus_to_llm.py**: Parses Nessus scan results
- **vulnerability_classifier.py**: Enriches vulnerabilities with CWE/MITRE data

## Output

The agent generates comprehensive reports in `data/agent_results/`:
- **Executive Summary**: High-level findings and risk assessment
- **Technical Details**: Step-by-step exploitation attempts
- **Validation Results**: Success/failure confirmation
- **Remediation Advice**: Recommended security improvements
