# 🚀 START HERE - Simple Guide

**Don't worry about all the files! You only need to know about 3 things:**

---

## 📍 The Only 3 Things You Need

### 1️⃣ **Put Your Nessus Scans Here:**
```
data/input/
```
Drop your `.nessus` files in this folder. That's it.

---

### 2️⃣ **Run This One Command:**
```bash
python scripts/parse_and_classify.py data/input/YOUR_SCAN.nessus data/output/result.json
```

Replace `YOUR_SCAN.nessus` with your actual filename.

---

### 3️⃣ **Get Your Results Here:**
```
data/output/result.json
```
This file has everything your RL agent needs!

---

## 🎯 That's It! 

Everything else is automatic. You don't need to touch anything else.

---

## 🔧 Optional: If You Want More Control

### Filter by Severity (Only Critical & High):
```bash
python scripts/parse_and_classify.py \
    data/input/scan.nessus \
    data/output/result.json \
    --severity 3 4
```

### Filter by CVSS Score (7.0+):
```bash
python scripts/parse_and_classify.py \
    data/input/scan.nessus \
    data/output/result.json \
    --min-cvss 7.0
```

---

## 📂 Files You Can Ignore

**99% of files are internal stuff. You don't need to touch:**
- `parser/` - Internal parser code
- `classifier/` - Internal classifier code
- `tests/` - Automated tests
- `tools/` - Internal CLI tools
- `schemas/` - Internal schemas
- `examples/` - Code examples (optional reading)
- `docs/` - Documentation (read if curious)

**The only folders you care about:**
- ✅ `data/input/` - Put scans here
- ✅ `data/output/` - Get results here

---

## 🆘 Need Help?

1. **Can't run the script?**
   ```bash
   pip install -r requirements.txt
   ```

2. **Want to see what your RL agent gets?**
   ```bash
   cat data/output/result.json | head -50
   ```

3. **Want to test if it works?**
   ```bash
   # Use the sample scan that's already there
   python scripts/parse_and_classify.py \
       data/input/ms2_scan.nessus \
       data/output/test.json
   ```

4. **Want to understand how it works?**
   - Read `HOW_IT_WORKS.md` - Detailed explanation
   - Read `WORKFLOW.md` - Visual workflow diagram

---

## 📊 What's in the Output?

Your `result.json` contains vulnerabilities with:
- ✅ **CWE categories** (weakness types)
- ✅ **MITRE ATT&CK** techniques & tactics
- ✅ **Priority score** (0-10, higher = more critical)
- ✅ **Suggested tools** (metasploit, nmap, etc.)
- ✅ **Validation strategy** (how to test if real)
- ✅ **Expected impact** (RCE, data leak, etc.)
- ✅ **Next steps** (what to do)

Perfect for your RL agent!

---

## 🎓 Quick Example

```bash
# 1. Put your scan in data/input/
cp ~/Downloads/my_scan.nessus data/input/

# 2. Run the pipeline
python scripts/parse_and_classify.py \
    data/input/my_scan.nessus \
    data/output/my_results.json

# 3. Check the results
cat data/output/my_results.json

# 4. Feed to your RL agent
python your_rl_agent.py data/output/my_results.json
```

---

## ✅ Summary

| What | Where | What to Do |
|------|-------|------------|
| **Input** | `data/input/` | Put `.nessus` files here |
| **Run** | One command | `python scripts/parse_and_classify.py ...` |
| **Output** | `data/output/` | Get results here for RL agent |

**That's all you need to know!** 🎉
