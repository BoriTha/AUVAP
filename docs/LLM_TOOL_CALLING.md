# LLM Tool Calling for Metasploit Search

## Problem Statement

Previously, the Metasploit integration relied on **rigid pattern matching**:
- ❌ Exact string matching: `"vsftpd 2.3.4"` would match, but `"vsftpd 2.3.5"` wouldn't
- ❌ Fuzzy matching had limited flexibility
- ❌ Failed when version information was missing (e.g., `"UnrealIRCd unknown"`)
- ❌ LLM couldn't make intelligent search decisions

## New Solution: LLM-Powered Search

Now, the **LLM has direct access to Metasploit** via tool calling:

### How It Works

```python
# Old way: Rigid pattern matching
if service_sig == "vsftpd 2.3.4":
    return exploit_module
else:
    return None  # ❌ Failed!

# New way: LLM-powered search
search_msf_modules(
    query="vsftpd backdoor",  # ✓ Free-form search
    service="vsftpd",
    version="2.3.4",
    msf_wrapper=msf
)
# Returns: List of ALL matching modules with detailed metadata
```

### LLM Tool Definition

The LLM can call this tool:

```json
{
  "name": "search_msf_modules",
  "description": "Search Metasploit's exploit database with ANY search query...",
  "parameters": {
    "query": {
      "type": "string",
      "description": "Free-form search query. Examples: 'vsftpd', 'samba usermap', 'backdoor ftp', 'unreal irc'"
    },
    "service": "Optional service name",
    "version": "Optional version",
    "port": "Optional port number"
  }
}
```

## LLM Search Strategies

The LLM can now use **intelligent search strategies**:

### Strategy 1: Multiple Query Attempts

```
Target: UnrealIRCd (version unknown)

LLM tries:
1. search_msf_modules(query="unrealircd")
   → ✓ Found: exploit/unix/irc/unreal_ircd_3281_backdoor

2. If failed, try: search_msf_modules(query="unreal irc backdoor")
3. If failed, try: search_msf_modules(query="irc 3.2.8")
```

### Strategy 2: Keyword-Based Search

```
Target: vsftpd 2.3.4

LLM knows this is a backdoor, so searches:
- "vsftpd backdoor" → ✓ Found
- "vsftpd 2.3.4" → ✓ Found
- "ftp backdoor" → ✓ Found related modules
```

### Strategy 3: Broad-to-Narrow Search

```
Target: Samba smbd 3.0.20-Debian

LLM searches broadly first:
1. search_msf_modules(query="samba") → 10 modules found
2. LLM analyzes results: "4 are exploits, 6 are auxiliary"
3. LLM filters: "I'll use the one with 'excellent' rank"
4. LLM selects: exploit/multi/samba/usermap_script
```

### Strategy 4: Context-Aware Search

```
Target: Service on port 1524

LLM reasoning:
- "Port 1524 is unusual"
- search_msf_modules(query="1524")
- If found: "Great! There's a known exploit"
- If not found: "Let me try Exploit-DB or CVE search"
```

## What the LLM Gets Back

The LLM receives **rich metadata** for each module:

```json
{
  "module": "exploit/unix/ftp/vsftpd_234_backdoor",
  "type": "exploit",
  "name": "VSFTPD v2.3.4 Backdoor Command Execution",
  "description": "This module exploits a malicious backdoor...",
  "rank": "excellent",
  "reliability_score": 5,
  "disclosure_date": "2011-07-03",
  "ports": [21],
  "required_options": ["RHOSTS", "RPORT"],
  "source": "manual",
  "note": "This is a manually curated mapping with verified reliability"
}
```

The LLM can then make **informed decisions**:
- "This module has 'excellent' rank - I'll use it!"
- "This requires LHOST and LPORT - I need to set those"
- "This is for port 21, but my target is port 2121 - might still work"

## Benefits

### 1. **Handles Unknown Versions**

```
Before: "UnrealIRCd unknown" → ❌ No match
After:  "UnrealIRCd unknown" → LLM searches "unrealircd" → ✓ Found
```

### 2. **Multiple Search Strategies**

```
LLM can try:
- Product name only: "vsftpd"
- Version specific: "vsftpd 2.3.4"
- Vulnerability type: "vsftpd backdoor"
- CVE: "CVE-2011-2523"
```

### 3. **Intelligent Module Selection**

```
If multiple modules found, LLM:
- Ranks by reliability score
- Filters by module type (exploit vs auxiliary)
- Considers disclosure date
- Checks required options
- Makes informed decision
```

### 4. **Natural Language Understanding**

```
LLM can understand:
- "Find exploits for FTP service" → Searches "ftp exploit"
- "This looks like a backdoor" → Searches "backdoor"
- "Samba is vulnerable" → Searches "samba"
```

## Real-World Example

### Metasploitable 2 Scan Results

```json
{
  "port": 6667,
  "service": "irc",
  "product": "UnrealIRCd",
  "version": "unknown"
}
```

### Old System (Rigid Matching)

```python
service_sig = "UnrealIRCd unknown"
module = msf_wrapper.get_module_info(service_sig)
# Returns: None ❌

print("🤖 No cached/MSF exploit found, will generate new one")
# LLM generates exploit from scratch (slow, error-prone)
```

### New System (LLM Tool Calling)

```python
# LLM calls tool
results = search_msf_modules(
    query="unrealircd",
    service="unrealircd",
    msf_wrapper=msf
)

# Returns:
[
  {
    "module": "exploit/unix/irc/unreal_ircd_3281_backdoor",
    "rank": "excellent",
    "reliability_score": 5,
    "description": "Backdoor in UnrealIRCd 3.2.8.1",
    ...
  }
]

# LLM decision:
"I found exploit/unix/irc/unreal_ircd_3281_backdoor with excellent rank.
I'll use this instead of generating new exploit code!"
```

## Tool Calling Flow

```
┌─────────────────────────────────────────────────────────────┐
│ Agent receives target: UnrealIRCd (version unknown)        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LLM analyzes: "I see 'UnrealIRCd' without version.         │
│ Let me search Metasploit database first."                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LLM calls: search_msf_modules(query="unrealircd")          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ MSF RPC returns:                                            │
│ [exploit/unix/irc/unreal_ircd_3281_backdoor]               │
│ Rank: excellent, Ports: [6667], Type: exploit              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ LLM decides: "Perfect! This module has excellent rank      │
│ and matches port 6667. I'll use this exploit."             │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ Execute: msf_wrapper.run_exploit(                           │
│   "exploit/unix/irc/unreal_ircd_3281_backdoor",            │
│   {"RHOSTS": target_ip, "RPORT": 6667}                     │
│ )                                                           │
└─────────────────────────────────────────────────────────────┘
```

## Performance Comparison

| Metric | Old (Rigid Matching) | New (LLM Tool Calling) |
|--------|----------------------|------------------------|
| **UnrealIRCd unknown** | ❌ Failed → Generate new | ✓ Found → Use MSF module |
| **vsftpd 2.3.4** | ✓ Exact match | ✓ Found (multiple ways) |
| **Samba smbd 3.0.20-Debian** | ✓ Fuzzy match | ✓ Found (with ranking) |
| **Linux telnetd unknown** | ❌ Failed | ✓ Found (product match) |
| **Search flexibility** | 1-2 patterns | Unlimited queries |
| **LLM understanding** | None | Full context |

## Future Enhancements

The LLM tool calling system can be extended with:

1. **CVE Search Integration**
   ```python
   search_msf_modules(cve="CVE-2011-2523")
   ```

2. **Exploit-DB Integration**
   ```python
   search_exploit_db(service="vsftpd", platform="linux")
   ```

3. **NVD Database Query**
   ```python
   query_cve_database(cve_id="CVE-2011-2523")
   ```

4. **Multi-Tool Orchestration**
   ```python
   # LLM can chain tools:
   msf_results = search_msf_modules(query="vsftpd")
   if not msf_results:
       edb_results = search_exploit_db(service="vsftpd")
       if not edb_results:
           cve_info = query_cve_database(cve="CVE-2011-2523")
   ```

## Code Changes

### 1. Updated `search_msf_modules()` in `llm_tools.py`

- ✅ Added `query` parameter for free-form search
- ✅ Direct MSF RPC search (comprehensive)
- ✅ Returns detailed metadata (rank, description, ports)
- ✅ Sorts by reliability score
- ✅ Manual mapping gets highest priority

### 2. Updated Tool Definition

```python
{
  "name": "search_msf_modules",
  "parameters": {
    "query": {"type": "string", "required": True},  # ← New!
    "service": {"type": "string", "optional": True},
    ...
  }
}
```

### 3. Updated `execute_tool()` in `llm_tools.py`

```python
if tool_name == "search_msf_modules":
    return search_msf_modules(
        query=arguments.get("query", arguments.get("service", "")),
        service=arguments.get("service"),
        ...
    )
```

### 4. Enhanced Fuzzy Matching in `msf_wrapper.py`

```python
# Product-only match for unknown versions
if 'unknown' in sig_parts:
    return module_info  # ✓ Still works as fallback
```

## Summary

**Before:** Rigid pattern matching failed on `"UnrealIRCd unknown"`
**After:** LLM intelligently searches Metasploit and finds the exploit

The LLM can now:
- 🧠 **Think** about what to search for
- 🔍 **Try** multiple search strategies
- 📊 **Analyze** results with detailed metadata
- ✅ **Choose** the best exploit module
- 🚀 **Execute** with confidence

This is a **game-changer** for automated penetration testing!
