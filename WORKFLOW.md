# 🔄 How Everything Works Together

## The Complete Workflow

```
┌─────────────────┐
│  Nessus Scan    │  You run a Nessus vulnerability scan
│  (.nessus file) │
└────────┬────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  STEP 1: PARSER                                     │
│  (parser/nessus_to_llm.py)                         │
│                                                     │
│  Reads Nessus XML and extracts:                    │
│  • Host IP (h)                                     │
│  • Port (p)                                        │
│  • Severity (s)                                    │
│  • CVE ID (c)                                      │
│  • CVSS Score                                      │
│  • Description                                     │
│  • Solution                                        │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  Parsed JSON                                        │
│  {                                                  │
│    "h": "192.168.1.100",                           │
│    "p": 6667,                                      │
│    "s": 4,                                         │
│    "c": "CVE-2010-2075",                           │
│    "cvss": 10.0,                                   │
│    "pn": "UnrealIRCd Backdoor"                     │
│  }                                                  │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  STEP 2: CLASSIFIER                                 │
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
│  Enriched JSON (RL-Ready)                          │
│  {                                                  │
│    "original": { /* raw data */ },                 │
│    "classification": {                             │
│      "cwe": ["CWE-912"],                           │
│      "mitre_attack": {                             │
│        "tactics": ["Persistence"],                 │
│        "techniques": ["T1554"]                     │
│      },                                            │
│      "priority_score": 10.0,                       │
│      "rl_agent_hints": {                           │
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
│  STEP 3: YOUR RL AGENT                             │
│                                                     │
│  For each vulnerability:                           │
│  1. Read priority_score → Attack highest first    │
│  2. Read suggested_tools → Load tools             │
│  3. Read validation_strategy → Plan attack        │
│  4. Execute next_steps → Run exploit              │
│  5. Record results → Generate report              │
└────────┬────────────────────────────────────────────┘
         │
         ↓
┌─────────────────────────────────────────────────────┐
│  RESULTS                                           │
│                                                     │
│  ✅ Vulnerability confirmed: CVE-2010-2075         │
│  ✅ Exploitation successful: RCE achieved          │
│  ✅ Report generated with replication steps        │
│                                                     │
│  → Pentester can verify manually                  │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 What Each Component Does

### Parser (nessus_to_llm.py)
**Input:** Nessus XML file  
**Does:** Extracts vulnerability data into clean JSON  
**Output:** Structured vulnerability list

### Classifier (vulnerability_classifier.py)
**Input:** Parsed vulnerability JSON  
**Does:** Adds intelligence (CWE, MITRE, attack plans)  
**Output:** RL-ready enriched JSON

### Your RL Agent
**Input:** Enriched vulnerability JSON  
**Does:** Executes attacks, validates exploits  
**Output:** Penetration testing reports

---

## 🔍 Example Flow

```
Nessus Scan
    ↓
"Found UnrealIRCd on 192.168.1.100:6667"
    ↓
Parser extracts:
    • CVE-2010-2075
    • CVSS: 10.0
    • Severity: Critical
    ↓
Classifier enriches:
    • CWE-912 (Hidden Functionality)
    • T1554 (Backdoor)
    • Priority: 10.0
    • Tools: [metasploit, netcat]
    • Steps: [1. Connect, 2. Send payload, 3. Verify]
    ↓
RL Agent executes:
    1. nc 192.168.1.100 6667
    2. Send: AB;system('whoami');
    3. Receives: root
    ↓
Result:
    ✅ Vulnerability confirmed!
    ✅ Remote code execution as root
    ✅ Report generated
```

---

## 💡 Why This Matters

**Without Classifier:**
- RL agent gets raw CVE numbers
- No idea how to test them
- Random/inefficient attacks

**With Classifier:**
- RL agent gets attack plans
- Knows exactly what to do
- Efficient, prioritized testing
- Actionable results

---

## 🚀 One Command Does It All

```bash
python scripts/parse_and_classify.py \
    data/input/scan.nessus \
    data/output/rl_ready.json
```

This runs:
1. Parser (Nessus → JSON)
2. Classifier (JSON → RL-Ready)
3. Saves results

Then your RL agent just reads `rl_ready.json` and goes! 🎯
