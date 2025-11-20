# 🔄 How Everything Works Together

## The Complete Workflow

```
┌─────────────────┐
│  START HERE     │  One command to rule them all
│  run_pentest.sh │
└────────┬────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  STEP 1: AUTOMATED SCANNING                        │
│  (core/nmap_scanner.py)                            │
│                                                     │
│  LLM Agent performs:                               │
│  • Network discovery                               │
│  • Port scanning                                   │
│  • Service identification                          │
│  • Vulnerability detection                         │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  OPTIONAL: NESSUS IMPORT                           │
│  (parser/nessus_to_llm.py)                         │
│                                                     │
│  If you have existing scans:                       │
│  • Reads Nessus XML                                │
│  • Extracts vulnerability data                     │
│  • Converts to structured JSON                     │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  STEP 2: INTELLIGENT CLASSIFICATION                 │
│  (classifier/vulnerability_classifier.py)           │
│                                                     │
│  3-Tier Classification:                            │
│                                                     │
│  Tier 1: CVE Lookup (95% confidence)               │
│  ├─ Check CVE database                            │
│  └─ Get CWE + MITRE mappings                      │
│                                                     │
│  Tier 2: Pattern Match (85% confidence)            │
│  ├─ Scan for keywords (backdoor, injection, etc)  │
│  └─ Match to 12+ attack patterns                  │
│                                                     │
│  Tier 3: Generic Fallback (30% confidence)         │
│  ├─ Use port analysis                             │
│  └─ Use CVSS/severity                             │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  Enriched JSON (LLM-Ready)                         │
│  {                                                  │
│    "original": { /* raw data */ },                 │
│    "classification": {                             │
│      "cwe": ["CWE-912"],                           │
│      "mitre_attack": {                             │
│        "tactics": ["Persistence"],                 │
│        "techniques": ["T1554"]                     │
│      },                                            │
│      "priority_score": 10.0,                       │
│      "llm_agent_hints": {                          │
│        "suggested_tools": ["metasploit"],          │
│        "validation_strategy": "...",               │
│        "next_steps": ["1...", "2...", "3..."]      │
│      }                                             │
│    }                                               │
│  }                                                  │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  STEP 3: LLM-POWERED EXPLOITATION                   │
│  (agent_mode.py)                                │
│                                                     │
│  Smart Triage Agent executes:                      │
│  1. Priority ranking → Attack highest first       │
│  2. Tool selection → Load appropriate tools       │
│  3. Attack planning → LLM generates strategies    │
│  4. Execution → Run exploits automatically        │
│  5. Results → Record outcomes & generate reports  │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  RESULTS                                           │
│                                                     │
│  ✅ Vulnerabilities discovered & classified         │
│  ✅ Exploitation attempts executed                  │
│  ✅ Success/failure documented                      │
│  ✅ Detailed reports generated                     │
│  ✅ Replication steps provided                     │
│                                                     │
│  → Complete automated pentest report               │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 What Each Component Does

### Automated Scanner (nmap_scanner.py)
**Input:** Target IP address  
**Does:** Performs network discovery and vulnerability scanning  
**Output:** Raw scan results

### Parser (nessus_to_llm.py) - Optional
**Input:** Nessus XML file  
**Does:** Extracts vulnerability data into clean JSON  
**Output:** Structured vulnerability list

### Classifier (vulnerability_classifier.py)
**Input:** Scan results or parsed vulnerability JSON  
**Does:** Adds intelligence (CWE, MITRE, attack plans)  
**Output:** LLM-ready enriched JSON

### LLM Agent (Smart Triage)
**Input:** Enriched vulnerability JSON  
**Does:** Executes attacks, validates exploits, learns from results  
**Output:** Complete penetration testing reports

---

## 🔍 Example Flow

```
./run_pentest.sh agent 192.168.1.100
    ↓
APFA Agent scans:
    • Discovers UnrealIRCd on 192.168.1.100:6667
    • Identifies CVE-2010-2075
    • CVSS: 10.0, Severity: Critical
    ↓
Classifier enriches:
    • CWE-912 (Hidden Functionality)
    • T1554 (Backdoor)
    • Priority: 10.0
    • Tools: [metasploit, netcat]
    • Steps: [1. Connect, 2. Send payload, 3. Verify]
    ↓
LLM Agent executes:
    1. nc 192.168.1.100 6667
    2. Send: AB;system('whoami');
    3. Receives: root
    ↓
Result:
    ✅ Vulnerability confirmed!
    ✅ Remote code execution as root
    ✅ Detailed report generated in data/agent_results/
```

---

## 💡 Why This Matters

**Without Intelligence:**
- LLM agent gets raw vulnerability data
- No context or attack strategies
- Inefficient, random testing

**With APFA:**
- LLM agent gets complete attack plans
- Knows exactly what to do and how
- Efficient, prioritized testing
- Actionable results with detailed reports

---

## 🚀 One Command Does It All

```bash
./run_pentest.sh agent 192.168.1.100
```

This runs:
1. Automated scanning (Network discovery)
2. Classification (Intelligence enrichment)
3. LLM exploitation (Smart triage)
4. Report generation (Complete documentation)

Everything is automated - just check `data/agent_results/` for your report! 🎯
