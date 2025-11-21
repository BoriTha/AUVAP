# AUVAP Terminal TUI - Classic Terminal Interface

A classic terminal TUI for AUVAP that solves focus management issues in original CLI with proper keyboard controls.

## Features

- **Proper Focus Management**: No more jumping to bottom of screen!
- **Classic Terminal Look**: ASCII art and box drawing characters
- **Full Keyboard Navigation**: Arrow keys, number shortcuts, ESC, etc.
- **Visual Feedback**: Highlighted selections and status messages
- **Settings Management**: Interactive configuration interface
- **Real-time Progress**: Step-by-step workflow execution
- **Cross-Platform**: Works on Linux, macOS, and Windows

## Quick Start

### Option 1: Terminal TUI (Recommended)
```bash
python apfa_terminal_tui.py
```

### Option 2: Using Launcher Script
```bash
./run_terminal_tui.sh
```

### Option 3: Modern TUI (Alternative)
```bash
python apfa_tui.py
```

### Option 4: With CLI Fallback
```bash
python apfa_terminal_tui.py --cli  # Falls back to original CLI if needed
```

### Option 2: Using Launcher Script
```bash
./run_tui.sh
```

### Option 3: With CLI Fallback
```bash
python apfa_tui.py --cli  # Falls back to original CLI if needed
```

## Navigation

### Main Menu
- **Arrow Keys**: Navigate menu options
- **Enter**: Select highlighted option
- **q**: Quit application
- **Ctrl+C**: Quit application

### Settings Screen
- **Tab/Shift+Tab**: Navigate between fields
- **Enter**: Confirm input
- **Ctrl+S**: Save settings
- **Escape**: Return to main menu

### Workflow Screens
- **Escape**: Return to main menu
- **q**: Quit application

## Screens

### 1. Main Menu
- Vulnerability Assessment
- Auto Pentesting  
- Settings & Configuration
- Exit

### 2. Vulnerability Assessment
- Start vulnerability scans
- Configure target settings
- Real-time progress logs
- Results notification

### 3. Auto Pentesting
- Launch automated pentests
- Monitor progress in real-time
- View results and logs

### 4. Settings & Configuration
- **Network Settings**: Target IP configuration
- **Safety Settings**: VM check requirements
- **LLM Configuration**: Model selection
- Save/Reset functionality

## Configuration

Settings are saved to:
```
apfa_agent/config/agent_config.yaml
```

### Default Configuration
```yaml
target:
  ip: 127.0.0.1
scanning:
  mode: auto
  sudo: false
llm:
  models:
    - name: gpt-4
safety:
  require_vm: true
execution:
  mode: safe
```

## Requirements

- Python 3.8+
- textual>=0.41.0
- pyyaml>=6.0

## Installation

```bash
# Install dependencies
pip install textual>=0.41.0 pyyaml>=6.0

# Run TUI
python apfa_tui.py
```

## Troubleshooting

### Import Errors
If you get import errors, ensure you're running from the project root:
```bash
cd /path/to/AUVAP
python apfa_tui.py
```

### Terminal Issues
- Ensure your terminal supports ANSI colors
- Minimum recommended size: 80x24
- For best experience, use a modern terminal emulator

### Performance
The TUI is optimized for performance:
- Minimal CPU usage
- Responsive UI updates
- Efficient memory management

## Comparison with CLI

| Feature | CLI | TUI |
|---------|-----|-----|
| Focus Management | ❌ Jumps to bottom | ✅ Proper focus |
| Terminal Size Support | ❌ Limited | ✅ Responsive |
| Visual Feedback | ❌ Basic | ✅ Rich |
| Keyboard Shortcuts | ❌ Limited | ✅ Full |
| Settings UI | ❌ Command-line | ✅ Interactive |
| Real-time Updates | ❌ Scrolling issues | ✅ Smooth |

## Development

The TUI is built with [Textual](https://textual.textual.io/), a modern Python TUI framework.

### Architecture
- `apfa_tui.py`: Main TUI application
- `SimpleConfigManager`: Configuration handling
- Screen-based architecture for navigation
- Reactive UI components

### Extending
To add new screens:
1. Create a new Screen class
2. Add it to the `SCREENS` dictionary
3. Implement navigation logic

## License

Same as the main AUVAP project.