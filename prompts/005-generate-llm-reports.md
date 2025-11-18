```xml
<objective>
LLM pipeline to generate GENERAL pentest reports from RL logs + classified vulns + topology. Structured MD/HTML: summary, topology viz, vuln table (CVSS/MITRE/proof), replication steps. Verify exploited vulns real. For any target, demo on ms2.
</objective>

<context>
Inputs: ANY classified.json, attack_graph.json, rl_logs.jsonl.
Audience: Researchers verifying RL auto-pentests.
</context>

<requirements>
1. Load data sources.
2. Analyze episodes: Paths, actions, MSF outputs, rewards.
3. Verify: Exploited vs classified (PoC evidence?).
4. Report: Exec sum, Mermaid topology, vuln table, replication bash.
5. CLI: python reporter/generate.py --classified JSON --topology JSON --logs JSONL --output MD
6. Test: ms2 data → full report.
</requirements>

<output>
- reporter/pentest_report_generator.py (CLI)
- docs/reports/general_autopentest_template.md
- examples/replicate_pentest.sh
</output>

<verification>
1. CLI → valid MD/HTML.
2. Report verifiable (commands/screenshots).
</verification>

<success_criteria>
- General, comprehensive reports proving RL pentesting.
</success_criteria>
```