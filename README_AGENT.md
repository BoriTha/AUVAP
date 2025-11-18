# DeepExploit Hybrid Agent

Autonomous pentesting agent combining Reinforcement Learning (PPO) with LLM-based exploit generation.

## Modes

### 1. LLM-Only Mode (Smart Triage)
Simple sequential attacking based on LLM ranking. No training required.
Best for: Quick scans, initial triage, verifying vulnerabilities.

```bash
python apfa_agent/main_agent.py --mode llm-only --target <IP>
```

### 2. Hybrid Mode (RL + LLM)
Full autonomous mode using trained PPO agent. Learns from experience and builds a skill library.
Best for: Deep penetration testing, finding complex paths, learning new skills.

```bash
python apfa_agent/main_agent.py --mode hybrid --target <IP>
```

### 3. Training Mode
Train the PPO agent in the environment.
Best for: Improving agent performance before deployment.

```bash
python apfa_agent/main_agent.py --mode train --timesteps 100000
```

### 4. Evaluation Mode
Evaluate the performance of a trained agent.

```bash
python apfa_agent/main_agent.py --mode eval --episodes 10
```

## Configuration

Configuration is in `apfa_agent/config/agent_config.yaml`.
Key settings:
- `target`: Default target IP
- `mode`: Hybrid mode settings (skill persistence)
- `agent`: PPO hyperparameters
- `llm`: LLM provider settings

## Safety

The agent includes a safety check to ensure it is running in a VM.
To bypass (NOT RECOMMENDED): `export APFA_SKIP_SAFETY_CHECK=true`
