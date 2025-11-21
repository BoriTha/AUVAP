# Quick Start: Metasploit Integration

## 🚀 Get Started in 3 Steps

### Step 1: Install Dependencies

```bash
# Install Metasploit Framework (if not already installed)
# Kali Linux: Already installed
# Ubuntu/Debian:
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Install Python RPC client
pip install pymetasploit3
```

### Step 2: Start Metasploit RPC Server

```bash
# Start msfrpcd in the background
msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1 &

# Verify it's running
ps aux | grep msfrpcd
```

### Step 3: Test the Integration

```bash
# Run the test suite
python test_msf_integration.py

# Expected output: "🎉 All tests passed! MSF integration is working."
```

---

## ✅ Quick Test: Exploit Metasploitable 2

```bash
# Make sure your Metasploitable 2 VM is running
# Default IP: 192.168.187.128 (update in config if different)

# Run the agent
python apfa_cli.py

# Select: "Auto Pentesting" or "Agent Mode"
# Watch the agent automatically use MSF exploits!
```

---

## 📖 Documentation

- **Full Guide**: `docs/MSF_INTEGRATION_GUIDE.md`
- **Implementation Details**: `MSF_IMPLEMENTATION_SUMMARY.md`
- **Test Suite**: `test_msf_integration.py`

---

## 🎯 What to Expect

When the agent encounters a known service (like vsftpd 2.3.4), you'll see:

```
[1/5] Attacking 192.168.187.128:21 (vsftpd)...
  🔍 Checking target connectivity...
  ✓ Target is reachable, proceeding with attack...
  🔍 Determining best exploitation method...
  🔫 Using manual MSF module: vsftpd 2.3.4
    • Module: exploit/unix/ftp/vsftpd_234_backdoor
    • Payload: cmd/unix/interact
    🚀 Executing with payload: cmd/unix/interact
    ⏳ Waiting for session (max 10s)...
    ✅ Session opened: 1
    📁 Evidence saved: data/agent_results/evidence/msf_session_1_*.txt
✅ SUCCESS!
```

---

## ⚙️ Configuration

Edit `apfa_agent/config/agent_config.yaml`:

```yaml
metasploit:
  enabled: true          # Set to false to disable MSF
  rpc_host: 127.0.0.1
  rpc_port: 55553
  username: msf
  password: msf123
  auto_discover: true    # Enable auto-discovery of new modules
```

---

## 🐛 Troubleshooting

### "Metasploit not connected"
```bash
# Start msfrpcd
msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1

# Check if running
ps aux | grep msfrpcd
```

### "No session created"
- Target may not be vulnerable
- Check if VM is online: `ping 192.168.187.128`
- Try different payload in `config/msf_modules.yaml`

### Test fails
```bash
# Update Metasploit
msfupdate

# Reinstall Python client
pip install --upgrade pymetasploit3

# Check MSF version
msfconsole --version
```

---

## 💡 Tips

1. **Always start msfrpcd first** before running the agent
2. **Check target connectivity** - ping the VM before pentesting
3. **Monitor MSF sessions** - open `msfconsole` in another terminal and run `sessions -l`
4. **Check logs** - Results saved in `data/agent_results/`

---

## 🎉 What's New

- ✅ Direct Metasploit exploit execution
- ✅ Intelligent exploit method selection (cached → MSF → LLM)
- ✅ Automatic post-exploitation evidence collection
- ✅ Learning system (successful exploits are cached)
- ✅ Fuzzy service matching
- ✅ Real-time MSF database search

---

## 📞 Need Help?

1. Run tests: `python test_msf_integration.py`
2. Check logs: `data/agent_results/`
3. Read full guide: `docs/MSF_INTEGRATION_GUIDE.md`
4. Verify msfrpcd: `ps aux | grep msfrpcd`
