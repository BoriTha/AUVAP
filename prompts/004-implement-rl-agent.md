```xml
<objective>
Implement general RL agent (Stable-Baselines3 PPO) for auto-pentesting ANY target: traverse attack graph, scan/exploit via MSF, max rewards. Train general policy, eval on test targets like Metasploitable2. Log episodes for reports.
</objective>

<context>
Uses 003: PentestEnv(target_ip, msf_config).
PPO/A2C. Train 100k+ steps on sim data. Eval: Exploit classified auto_pentestable vulns.
</context>

<requirements>
1. Load PentestEnv(target_ip='demo_ip').
2. PPO: model = PPO('MlpPolicy', env, verbose=1)  # or CNN for graph.
3. Train: model.learn(total_timesteps=100000)
4. Eval: Full episodes on target, exploit priorities.
5. Logs: JSONL (episodes: actions, rewards, msf_cmds, outputs).
6. CLI: python rl_agent/train.py --target-ip TARGET --msf-host MSF_IP
7. Test: ms2 → exploits 70%+ vulns.
</requirements>

<output>
- rl_agent/train_agent.py (CLI)
- rl_agent/eval_agent.py
- models/ppo_general.zip
- data/rl_logs/demo_episodes.jsonl
</output>

<verification>
1. Train converges.
2. Eval on ms2: Multiple exploits/shells.
3. Logs complete.
</verification>

<success_criteria>
- General agent exploits auto_pentestable vulns across targets.
</success_criteria>
```