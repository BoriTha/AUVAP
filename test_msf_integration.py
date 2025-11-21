#!/usr/bin/env python3
"""
Test script for Metasploit integration with APFA Agent.
Tests the full MSF execution pipeline.
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_msf_connection():
    """Test 1: Verify MSF RPC connection"""
    print("=" * 60)
    print("TEST 1: Metasploit RPC Connection")
    print("=" * 60)
    
    from apfa_agent.msf_wrapper import MetasploitWrapper
    
    try:
        msf = MetasploitWrapper()
        
        if msf.client:
            print("✅ Metasploit RPC connected successfully")
            print(f"   • Connected to Metasploit RPC")
            return True
        else:
            print("❌ Metasploit RPC not connected")
            print("   Make sure msfrpcd is running:")
            print("   $ msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1")
            return False
            
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

def test_module_lookup():
    """Test 2: Module lookup and fuzzy matching"""
    print("\n" + "=" * 60)
    print("TEST 2: Module Lookup")
    print("=" * 60)
    
    from apfa_agent.msf_wrapper import MetasploitWrapper
    
    try:
        msf = MetasploitWrapper()
        
        if not msf.client:
            print("⚠️  Skipping (MSF not connected)")
            return False
        
        # Test exact match
        print("\n📋 Testing exact match: 'vsftpd 2.3.4'")
        result = msf.get_module_info("vsftpd 2.3.4")
        
        if result:
            print(f"✅ Found module: {result.get('module')}")
            print(f"   • Source: {result.get('source')}")
            print(f"   • Reliability: {result.get('reliability')}")
            print(f"   • Payload: {result.get('payload')}")
        else:
            print("❌ No module found")
            return False
        
        # Test fuzzy match
        print("\n📋 Testing fuzzy match: 'samba smbd 3.0.20-debian'")
        result = msf.get_module_info("samba smbd 3.0.20-debian")
        
        if result:
            print(f"✅ Found module: {result.get('module')}")
            print(f"   • Source: {result.get('source')}")
        else:
            print("❌ No module found")
        
        # Test auto-discovery
        print("\n📋 Testing auto-discovery: 'apache 2.4.49'")
        result = msf.get_module_info("apache 2.4.49")
        
        if result:
            print(f"✅ Found module: {result.get('module')}")
            print(f"   • Source: {result.get('source')}")
            print(f"   • Confidence: {result.get('confidence', 'N/A')}")
        else:
            print("⚠️  No module found (expected for services not in manual mapping)")
        
        return True
        
    except Exception as e:
        print(f"❌ Module lookup failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_tool_manager_integration():
    """Test 3: ToolManager MSF integration"""
    print("\n" + "=" * 60)
    print("TEST 3: ToolManager MSF Integration")
    print("=" * 60)
    
    from apfa_agent.msf_wrapper import MetasploitWrapper
    from apfa_agent.tool_manager import ToolManager
    
    try:
        msf = MetasploitWrapper()
        tool_manager = ToolManager(msf_wrapper=msf)
        
        # Test decision making
        print("\n🎯 Testing exploit method selection:")
        
        services = [
            "vsftpd 2.3.4",
            "samba 3.0.20",
            "unrealircd 3.2.8.1",
            "apache 2.4.50"
        ]
        
        for service in services:
            print(f"\n   Service: {service}")
            method, data = tool_manager.get_exploit_method(service)
            print(f"   → Method: {method}")
            if data and method == "metasploit":
                print(f"   → Module: {data.get('module')}")
        
        return True
        
    except Exception as e:
        print(f"❌ ToolManager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_agent_initialization():
    """Test 4: Agent initialization with MSF"""
    print("\n" + "=" * 60)
    print("TEST 4: Agent Initialization")
    print("=" * 60)
    
    from apfa_agent.agent_mode import SmartTriageAgent
    
    try:
        print("\n🤖 Initializing SmartTriageAgent...")
        agent = SmartTriageAgent(config_path="apfa_agent/config/agent_config.yaml")
        
        if agent.msf_wrapper:
            print("✅ Agent initialized with Metasploit integration")
            print(f"   • MSF connected: {agent.msf_wrapper.client is not None}")
        else:
            print("⚠️  Agent initialized but MSF not available")
            print("   (This is OK if metasploit.enabled = false in config)")
        
        # Test tool manager integration
        if agent.tool_manager.msf_wrapper:
            print("✅ ToolManager has MSF wrapper")
        else:
            print("⚠️  ToolManager has no MSF wrapper")
        
        return True
        
    except Exception as e:
        print(f"❌ Agent initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_full_exploit_flow():
    """Test 5: Full exploit flow (DRY RUN - no actual exploit)"""
    print("\n" + "=" * 60)
    print("TEST 5: Full Exploit Flow (Simulation)")
    print("=" * 60)
    
    from apfa_agent.msf_wrapper import MetasploitWrapper
    from apfa_agent.tool_manager import ToolManager
    
    try:
        msf = MetasploitWrapper()
        tool_manager = ToolManager(msf_wrapper=msf)
        
        # Simulate target
        target_service = "vsftpd 2.3.4"
        target_ip = "192.168.187.128"
        target_port = 21
        
        print(f"\n🎯 Simulating attack on: {target_service}")
        print(f"   Target: {target_ip}:{target_port}")
        
        # Step 1: Get exploit method
        print("\n   Step 1: Determine exploit method")
        method, data = tool_manager.get_exploit_method(target_service)
        print(f"   → Method: {method}")
        
        if method == "metasploit" and data:
            print(f"   → Module: {data.get('module')}")
            print(f"   → Payload: {data.get('payload')}")
            print(f"   → Ports: {data.get('ports')}")
            
            # Step 2: Prepare options (but don't execute)
            print("\n   Step 2: Prepare execution options")
            options = {
                'RHOSTS': target_ip,
                'RHOST': target_ip,
                'RPORT': str(target_port)
            }
            print(f"   → Options: {options}")
            
            print("\n   ✅ Flow simulation complete")
            print("   (Actual exploit NOT executed - this is a dry run)")
            
        else:
            print(f"   ⚠️  Would use: {method}")
        
        return True
        
    except Exception as e:
        print(f"❌ Flow simulation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("APFA METASPLOIT INTEGRATION TEST SUITE")
    print("=" * 60)
    
    tests = [
        ("MSF RPC Connection", test_msf_connection),
        ("Module Lookup", test_module_lookup),
        ("ToolManager Integration", test_tool_manager_integration),
        ("Agent Initialization", test_agent_initialization),
        ("Full Exploit Flow", test_full_exploit_flow)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n❌ Test '{test_name}' crashed: {e}")
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! MSF integration is working.")
    else:
        print("\n⚠️  Some tests failed. Check the output above for details.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
