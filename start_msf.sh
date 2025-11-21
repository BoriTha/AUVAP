#!/bin/bash
# Start Metasploit RPC and run APFA Agent
# This script makes it easy to get started with MSF integration

echo "=========================================="
echo "APFA Agent - Metasploit Integration"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if msfrpcd is already running
if pgrep -x "msfrpcd" > /dev/null; then
    echo -e "${GREEN}✓${NC} msfrpcd is already running"
else
    echo -e "${YELLOW}→${NC} Starting Metasploit RPC server..."
    
    # Start msfrpcd in background
    msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1 &
    
    # Wait for it to start
    echo "  Waiting for msfrpcd to initialize..."
    sleep 5
    
    # Verify it started
    if pgrep -x "msfrpcd" > /dev/null; then
        echo -e "${GREEN}✓${NC} msfrpcd started successfully"
    else
        echo -e "${RED}✗${NC} Failed to start msfrpcd"
        echo "  Please install Metasploit Framework:"
        echo "  https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
        exit 1
    fi
fi

# Check if pymetasploit3 is installed
if python3 -c "import pymetasploit3" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} pymetasploit3 is installed"
else
    echo -e "${YELLOW}→${NC} Installing pymetasploit3..."
    pip install pymetasploit3
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} pymetasploit3 installed"
    else
        echo -e "${RED}✗${NC} Failed to install pymetasploit3"
        exit 1
    fi
fi

echo ""
echo "=========================================="
echo "Configuration:"
echo "  RPC Host: 127.0.0.1"
echo "  RPC Port: 55553"
echo "  Username: msf"
echo "  Password: msf123"
echo "=========================================="
echo ""

# Ask what to do
echo "What would you like to do?"
echo "  1) Run integration tests"
echo "  2) Start APFA agent"
echo "  3) Both (test then start)"
echo "  4) Stop msfrpcd and exit"
echo ""
read -p "Enter choice [1-4]: " choice

case $choice in
    1)
        echo ""
        echo "Running integration tests..."
        python3 test_msf_integration.py
        ;;
    2)
        echo ""
        echo "Starting APFA agent..."
        python3 apfa_cli.py
        ;;
    3)
        echo ""
        echo "Running integration tests..."
        python3 test_msf_integration.py
        
        if [ $? -eq 0 ]; then
            echo ""
            echo -e "${GREEN}Tests passed!${NC} Starting agent..."
            sleep 2
            python3 apfa_cli.py
        else
            echo ""
            echo -e "${RED}Tests failed.${NC} Please fix issues before running agent."
            exit 1
        fi
        ;;
    4)
        echo ""
        echo "Stopping msfrpcd..."
        pkill -x msfrpcd
        echo -e "${GREEN}✓${NC} msfrpcd stopped"
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# Cleanup handler
cleanup() {
    echo ""
    echo "Cleaning up..."
    # Don't kill msfrpcd - let it keep running for future use
    echo "msfrpcd is still running. To stop it, run: pkill msfrpcd"
}

trap cleanup EXIT
