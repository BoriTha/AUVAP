#!/bin/bash
echo "Starting Metasploit RPC Server..."
msfrpcd -U msf -P msf123 -p 55553 -S -a 127.0.0.1
echo "Metasploit RPC Server started on port 55553"
