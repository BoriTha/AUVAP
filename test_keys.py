#!/usr/bin/env python3
"""Test key detection"""
import sys
import termios
import tty

def get_key():
    """Get single keypress"""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
        
        # Handle arrow keys and special keys
        if ch == '\x1b':
            # ESC was pressed, check if it's part of an escape sequence
            old_flags = termios.tcgetattr(fd)
            new_flags = old_flags[:]
            new_flags[6][termios.VMIN] = 0  # Min chars to read
            new_flags[6][termios.VTIME] = 1  # Timeout in deciseconds (0.1 sec)
            termios.tcsetattr(fd, termios.TCSANOW, new_flags)
            
            seq = sys.stdin.read(2)
            
            termios.tcsetattr(fd, termios.TCSANOW, old_flags)
            
            if seq == '[A':  # Up arrow
                return 'UP'
            elif seq == '[B':  # Down arrow
                return 'DOWN'
            elif seq == '[C':  # Right arrow
                return 'RIGHT'
            elif seq == '[D':  # Left arrow
                return 'LEFT'
            else:
                # Just ESC key pressed alone
                return f'ESC (seq={repr(seq)})'
        elif ch == '\r' or ch == '\n':  # Enter
            return 'ENTER'
        elif ch == '\x03':  # Ctrl+C
            return 'CTRL-C'
        elif ch == 'q' or ch == 'Q':
            return 'Q'
        else:
            return f'{repr(ch)}'
            
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

print("Press keys to test (q to quit):")
while True:
    key = get_key()
    print(f"Detected: {key}")
    if key in ['Q', 'CTRL-C']:
        break
print("\nDone!")
