#!/usr/bin/env python3
"""
AUVAP Terminal TUI Launcher
"""

import sys
import os

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

if __name__ == "__main__":
    try:
        from apfa_terminal_tui import main
        main()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error starting Terminal TUI: {e}")
        sys.exit(1)