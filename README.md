# APFA - Automated Pentesting & Vulnerability Assessment

Convert Nessus scans → Classify with NVD/MITRE → Feed to RL Agent for pentesting simulation.

---

## 🚀 Quick Start (3 Steps)

### 1. Install
```bash
pip install -r requirements.txt
```

### 2. Put Your Nessus Scan Here
```
data/input/your_scan.nessus
```

### 3. Run Pipeline
```bash
python scripts/parse_and_classify.py \
    data/input/your_scan.nessus \
    data/output/result.json
```

**Done!** Your results are in `data/output/result.json`

---

## 📁 What You Need to Know

```
APFA/
├── data/
│   ├── input/         ← PUT YOUR .nessus FILES HERE
│   └── output/        ← GET YOUR RESULTS HERE
│
└── scripts/
    └── parse_and_classify.py  ← RUN THIS SCRIPT
```

**Everything else is internal code - you don't need to touch it!**

---

## 🎯 What You Get

Your output JSON contains vulnerabilities enriched with:

- ✅ **CWE categories** - Weakness classification
- ✅ **MITRE ATT&CK** - Tactics & techniques
- ✅ **Priority score** - 0-10 ranking
- ✅ **Suggested tools** - metasploit, nmap, etc.
- ✅ **Validation strategy** - How to test if exploitable
- ✅ **Expected impact** - RCE, data leak, etc.
- ✅ **Next steps** - What to do

**Perfect for RL agent consumption!**

---

## 🔧 Optional Filters

### Filter by Severity (Critical & High only):
```bash
python scripts/parse_and_classify.py \
    data/input/scan.nessus \
    data/output/result.json \
    --severity 3 4
```

### Filter by CVSS Score:
```bash
python scripts/parse_and_classify.py \
    data/input/scan.nessus \
    data/output/result.json \
    --min-cvss 7.0
```

---

## 📊 Example Output

```json
{
  "id": "vuln_192.168.79.128_8180_171340",
  "original": {
    "h": "192.168.79.128",
    "p": 8180,
    "s": 4,
    "pn": "Apache Tomcat AJP Connector (Ghostcat)",
    "c": "CVE-2020-1745",
    "cvss": 9.8
  },
  "classification": {
    "cwe": ["CWE-94", "CWE-200"],
    "mitre_attack": {
      "tactics": ["Initial Access", "Execution"],
      "techniques": ["T1190", "T1059"]
    },
    "priority_score": 10.0,
    "rl_agent_hints": {
      "suggested_tools": ["metasploit", "custom_exploit"],
      "validation_strategy": "Check AJP port, attempt file read",
      "expected_impact": "Remote Code Execution",
      "next_steps": [
        "1. Identify AJP port (typically 8009)",
        "2. Send crafted AJP request",
        "3. Read sensitive files or upload JSP"
      ]
    }
  }
}
```

---

## 🧪 Test It Works

```bash
# Use the sample scan already in data/input/
python scripts/parse_and_classify.py \
    data/input/ms2_scan.nessus \
    data/output/test.json

# Check results
cat data/output/test.json | head -50
```

---

## 🆘 Troubleshooting

**Import errors?**
```bash
pip install -r requirements.txt
```

**Want to verify it's working?**
```bash
python -m pytest tests/ -v
```

**Need more control?** See `START_HERE.md` for detailed options.

---

## 📂 Project Structure

<details>
<summary>Click to expand (you don't need to know this)</summary>

```
APFA/
├── parser/              # Nessus XML → JSON parser
├── classifier/          # CWE/MITRE classifier
├── data/
│   ├── input/          # Your .nessus files
│   └── output/         # Results
├── scripts/            # Automation scripts
├── tests/              # Test suite
├── tools/              # CLI utilities
├── config/             # YAML configs
├── examples/           # Code examples
├── schemas/            # JSON schemas
└── docs/               # Documentation
```
</details>

---

## ✅ Status

- ✅ Parser: **96.2% tested**
- ✅ Classifier: **100% tested**  
- ✅ Integration: **Working**

---

## 📖 More Info

- **Simple guide**: `START_HERE.md`
- **Classifier details**: `classifier/README.md`
- **Validation report**: `docs/reports/parser_validation_report.md`

---

**Built for pentesters. Ready to use.** 🎯
