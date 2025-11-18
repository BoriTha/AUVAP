# How the Vulnerability Classifier Works

## 🎯 Simple Explanation

The classifier takes raw vulnerability data and **enriches it with intelligence** so your RL agent knows:
- What type of attack to use
- Which tools to use
- How to verify if it's exploitable
- What the expected impact is

---

## 🔄 The Classification Process

### Input (What Goes In)
Raw vulnerability from Nessus parser:
```json
{
  "id": "vuln_192.168.79.128_6667_46882",
  "h": "192.168.79.128",
  "p": 6667,
  "s": 4,
  "pn": "UnrealIRCd Backdoor Detection",
  "c": "CVE-2010-2075",
  "cvss": 10.0,
  "d": "The remote IRC server has a backdoor that allows remote code execution"
}
```

### Output (What Comes Out)
Enriched vulnerability with RL agent intelligence:
```json
{
  "id": "vuln_192.168.79.128_6667_46882",
  "original": { /* same as input */ },
  "classification": {
    "cwe": ["CWE-912"],
    "cwe_names": ["Hidden Functionality"],
    "mitre_attack": {
      "tactics": ["Persistence", "Execution"],
      "techniques": ["T1554", "T1059"],
      "technique_names": ["Compromise Client Software Binary", "Command and Scripting Interpreter"]
    },
    "categorization_source": "pattern_match",
    "exploitation_difficulty": "Low",
    "priority_score": 10.0,
    "rl_agent_hints": {
      "attack_type": "backdoor_exploitation",
      "attack_vector": "Network",
      "requires_auth": false,
      "suggested_tools": ["metasploit", "netcat", "nmap"],
      "validation_strategy": "Connect to port 6667, send specific payload, check for shell access",
      "expected_impact": "Remote Code Execution",
      "next_steps": [
        "1. Scan for port 6667",
        "2. Send backdoor trigger command",
        "3. Verify shell access with 'whoami'"
      ]
    }
  }
}
```

---

## 🧠 How It Classifies (3-Tier System)

### Tier 1: CVE Lookup (Highest Confidence - 95%)
```
IF vulnerability has a CVE ID:
  → Look it up in CVE database
  → Get known CWE categories
  → Get known MITRE ATT&CK mappings
  → Return high-confidence classification
```

**Example:**
- Input: CVE-2020-1745 (Ghostcat)
- Output: CWE-94 (Code Injection), T1190 (Exploit Public-Facing App)
- Confidence: 95%

---

### Tier 2: Pattern Matching (Medium Confidence - 85%)
```
IF no CVE or CVE lookup fails:
  → Scan vulnerability description for keywords
  → Match against 12+ known patterns:
      - Backdoor patterns
      - Weak credential patterns
      - Injection patterns
      - Crypto weakness patterns
      - Default credential patterns
      - etc.
  → Return pattern-based classification
```

**Example:**
- Input: "UnrealIRCd Backdoor Detection"
- Matches: "backdoor" keyword
- Output: CWE-912 (Hidden Functionality), T1554 (Backdoor)
- Confidence: 70%

---

### Tier 3: Generic Fallback (Low Confidence - 30%)
```
IF no CVE and no pattern match:
  → Use generic classification based on:
      - Port number (e.g., 80 = web, 22 = SSH)
      - CVSS score
      - Severity level
  → Return generic recommendations
```

**Example:**
- Input: Unknown vulnerability on port 443
- Output: Generic web attack, T1190, standard web tools
- Confidence: 30%

---

## 📊 The 12 Vulnerability Patterns

The classifier knows these attack types:

| Pattern | Keywords | Example |
|---------|----------|---------|
| **Backdoor** | backdoor, trojan, malicious code | UnrealIRCd backdoor |
| **Weak Credentials** | weak password, default creds | VNC password "password" |
| **Injection** | SQL injection, command injection | SQLi in web app |
| **Crypto Weakness** | weak cipher, SSL, TLS | Weak SSL ciphers |
| **Denial of Service** | DoS, crash, exhaust | Buffer overflow DoS |
| **Info Disclosure** | information leak, exposure | Directory listing |
| **Privilege Escalation** | privilege escalation, root | Local root exploit |
| **Authentication Bypass** | auth bypass, no auth | Anonymous FTP |
| **Path Traversal** | path traversal, directory | ../../../etc/passwd |
| **Deserialization** | deserialization, unserialize | Java deserialization |
| **End-of-Life** | end of life, unsupported | Tomcat 5.5.x EOL |
| **Missing Patch** | missing patch, update | Unpatched Apache |

---

## 🎯 What Your RL Agent Gets

For each vulnerability, the classifier provides:

### 1. **Attack Classification**
```json
{
  "cwe": ["CWE-912"],
  "mitre_attack": {
    "tactics": ["Persistence", "Execution"],
    "techniques": ["T1554", "T1059"]
  }
}
```
**Why?** So the RL agent knows what type of attack this is.

---

### 2. **Priority Score (0-10)**
```json
{
  "priority_score": 10.0
}
```
**Why?** So the RL agent knows which vulnerabilities to attack first.

**Calculation:**
- CVSS 9.0-10.0 = Priority 10.0 (Critical)
- CVSS 7.0-8.9 = Priority 7.0-8.0 (High)
- CVSS 4.0-6.9 = Priority 4.0-6.0 (Medium)
- Adjusted by exploit availability and impact

---

### 3. **Tool Recommendations**
```json
{
  "suggested_tools": ["metasploit", "netcat", "nmap"]
}
```
**Why?** So the RL agent knows which pentesting tools to use.

---

### 4. **Validation Strategy**
```json
{
  "validation_strategy": "Connect to port 6667, send payload, verify shell"
}
```
**Why?** So the RL agent knows HOW to test if the vulnerability is real.

---

### 5. **Exploitation Assessment**
```json
{
  "exploitation_difficulty": "Low",
  "requires_auth": false,
  "attack_vector": "Network"
}
```
**Why?** So the RL agent knows if it can actually exploit this.

---

### 6. **Step-by-Step Guide**
```json
{
  "next_steps": [
    "1. Scan for port 6667",
    "2. Send backdoor trigger",
    "3. Verify shell access"
  ]
}
```
**Why?** So the RL agent has a clear attack plan.

---

## 🤖 How Your RL Agent Uses This

```python
import json

# Load classified vulnerabilities
with open('data/output/result.json') as f:
    vulns = json.load(f)

# Sort by priority (highest first)
sorted_vulns = sorted(vulns, 
                     key=lambda x: x['classification']['priority_score'], 
                     reverse=True)

# Attack each vulnerability
for vuln in sorted_vulns:
    target = vuln['original']['h']
    port = vuln['original']['p']
    
    # Get attack plan
    tools = vuln['classification']['rl_agent_hints']['suggested_tools']
    strategy = vuln['classification']['rl_agent_hints']['validation_strategy']
    steps = vuln['classification']['rl_agent_hints']['next_steps']
    
    # Execute attack
    print(f"Attacking {target}:{port}")
    print(f"Using tools: {tools}")
    print(f"Strategy: {strategy}")
    
    for step in steps:
        print(f"  {step}")
        # Your RL agent executes each step
        # ...
    
    # Report results
    if attack_successful:
        print(f"✅ Vulnerability confirmed!")
        generate_report(vuln)
```

---

## 🔍 Example: Full Classification Flow

### Input Vulnerability
```
Port: 6667
Name: UnrealIRCd Backdoor Detection
CVE: CVE-2010-2075
CVSS: 10.0
```

### Step 1: Check CVE Database
```
✅ CVE-2010-2075 found!
→ CWE: CWE-912 (Hidden Functionality)
→ Known exploit: Yes (Metasploit module exists)
```

### Step 2: Pattern Analysis
```
✅ Description contains "backdoor"
→ Pattern match: backdoor_exploitation
→ MITRE: T1554 (Compromise Software Binary)
→ MITRE: T1059 (Command Interpreter)
```

### Step 3: Port Analysis
```
Port 6667 = IRC service
→ Attack vector: Network
→ Requires auth: No
```

### Step 4: Generate RL Hints
```
Priority: 10.0 (CVSS 10.0 + known exploit)
Tools: metasploit, netcat, nmap
Strategy: "Send backdoor trigger command to port 6667"
Difficulty: Low (public exploit available)
Impact: Remote Code Execution
Steps:
  1. Scan for port 6667
  2. Connect with netcat
  3. Send: AB;system('whoami');
  4. Verify shell access
```

### Final Output
```json
{
  "id": "vuln_192.168.79.128_6667_46882",
  "classification": {
    "priority_score": 10.0,
    "rl_agent_hints": {
      "attack_type": "backdoor_exploitation",
      "suggested_tools": ["metasploit", "netcat"],
      "validation_strategy": "Send backdoor trigger, verify RCE",
      "next_steps": [...],
      "expected_impact": "Remote Code Execution"
    }
  }
}
```

---

## ⚡ Why This Works for RL Agents

### Traditional Approach ❌
```
Vulnerability scan → Raw CVE list → Manual analysis → Manual testing
```
**Problem:** RL agent doesn't know HOW to test vulnerabilities.

### Our Approach ✅
```
Vulnerability scan → Parser → Classifier → RL-Ready Instructions
```
**Benefit:** RL agent gets:
- Prioritized target list
- Tool recommendations
- Attack strategies
- Step-by-step plans
- Expected outcomes

---

## 🎓 Summary

**What it does:**
Takes raw vulnerability data and adds intelligence (CWE, MITRE, attack plans)

**How it works:**
1. CVE lookup (if CVE exists)
2. Pattern matching (12+ attack patterns)
3. Generic fallback (based on port/severity)

**What your RL agent gets:**
- Priority scores (what to attack first)
- Tool suggestions (what to use)
- Validation strategies (how to test)
- Step-by-step plans (what to do)
- Expected impact (what happens)

**Result:**
Your RL agent can autonomously test vulnerabilities and generate reports! 🎯

---

## ❓ FAQ: Why LangChain/API If It's Pattern-Based?

### Q: I see LangChain imports. Does this use LLM/API calls?

**A: NO, by default it does NOT use LLM or make API calls!**

The classifier has **3 modes**:

| Mode | LLM? | API Calls? | Cost | Speed | Default? |
|------|------|------------|------|-------|----------|
| **pattern** | ❌ No | ❌ No | FREE | Fast (10ms) | ✅ Yes |
| **hybrid** | ❌ No | ❌ No | FREE | Fast (15ms) | ✅ Yes |
| **rag** | ✅ Yes | ✅ Yes | $$ Paid | Slow (2s) | ❌ No |

### Default Behavior (What You Use):

```bash
# This command uses "hybrid" mode (NO LLM, NO API calls)
python scripts/parse_and_classify.py \
    data/input/scan.nessus \
    data/output/result.json
```

**No API key required. 100% offline. $0 cost.**

---

### Optional: Enable RAG Mode

If you have **really weird/unknown vulnerabilities** that don't match patterns:

```bash
# 1. Set API key in .env
echo "OPENROUTER_API_KEY=your_key" > .env

# 2. Run with --enable-rag flag
python scripts/parse_and_classify.py \
    data/input/scan.nessus \
    data/output/result.json \
    --enable-rag
```

**Now it WILL use LLM for complex cases (costs money, slower).**

---

### Why Build It This Way?

**Flexibility!**

- 95% of vulnerabilities → Pattern matching works fine (free, fast)
- 5% edge cases → RAG mode for deep analysis (optional, paid)

The LangChain code is **optional enhancement**, not a requirement.

---

### How to Check What Mode You're Using:

```python
# In your code
from classifier.vulnerability_classifier import VulnerabilityClassifier

# This is the default (NO LLM)
classifier = VulnerabilityClassifier(mode="hybrid")

# This enables LLM (COSTS MONEY)
classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=True)
```

**Bottom line: Unless you explicitly enable RAG mode, no LLM is used!**

