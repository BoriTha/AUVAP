```xml
<objective>
Improve and validate the existing Nessus parser and vulnerability classifier for GENERAL Nessus scans from ANY machine. Ensure accurate JSON output with filtering parameters for include/exclude vulns. Classify vulns into 'auto_pentestable' (CLI/script exploitable via MSF, no GUI, not enterprise-locked like always-open ports) vs 'non_auto_pentestable'. Categorize by NVD CVSS scores, MITRE ATT&CK tactics/techniques matching vuln/service/port. Test on provided ms2_scan.nessus (Metasploitable2 as demo). This is step 1-2 of educational/research auto-pentesting pipeline for paper/demo.
</objective>

<context>
Educational/research prototype for general auto-pentesting ANY target using RL agent + MSF. Steps: parse/classify Nessus → topology → RL env → agent → report.
Existing: parser/nessus_to_llm.py (excellent, supports filters). classifier/ has vulnerability_classifier.py, patterns.json.
Input Nessus: @data/input/ms2_scan.nessus (test case). General CLI accepts any .nessus.
Nmap example: @data/input/ms2-scan-result.xml.
Output JSON for LLM/RL: host, port, severity, cve, cvss, mitre_tactics, auto_pentestable (bool), attack_category (e.g., 'web', 'network', 'cred').
</context>

<requirements>
1. Validate/enhance parser/nessus_to_llm.py - test on ANY .nessus, e.g., ms2_scan.nessus → data/processed/test_vulns.json.
2. Filters: Params for enterprise exclusions (e.g., exclude port 80/443 if 'business critical'), RL limits (exclude GUI VNC/RDP).
3. Classifier: For each vuln:
   - NVD API/offline: CVSS v3, desc.
   - MITRE: Map pluginFamily/port/service/CVE (e.g., FTP→TA0008).
   - auto_pentestable: Query MSFconsole 'search cve:X' or pymetasploit3 → exists & CLI/script-only (no GUI). Flag enterprise_locked if port always-open/low-risk.
   - Categories: web, auth_bypass, rce, file_share, rpc/nfs, db, etc.
4. CLI: python scripts/classify.py --input PATH_TO_ANY_NESSUS.nessus --output JSON --filter exclude_enterprise --min_cvss 5.0
5. Test: ms2_scan.nessus → classify known MSF vulns correctly (e.g., vsftpd CVE-2011-2523: auto_pentestable=True).
</requirements>

<output>
- Update parser/nessus_to_llm.py (add classifier integration).
- classifier/general_vuln_classifier.py
- data/processed/ms2_classified.json (test output)
- scripts/classify.py (CLI)
- examples/classify_demo.py
- Update README.md, requirements.txt (nvdlib, pymetasploit3, stix2).
</output>

<verification>
1. !python scripts/classify.py --input data/input/ms2_scan.nessus → valid JSON.
2. auto_pentestable=True for MSF-exploitable vulns.
3. Handles general Nessus (test with synthetic if needed).
4. MSF search accuracy >90%.
</verification>

<success_criteria>
- General parser/classifier works on any Nessus, accurate MSF mapping, JSON ready for RL.
</success_criteria>
```