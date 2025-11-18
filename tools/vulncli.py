#!/usr/bin/env python3
"""
Vulnerability CLI Tool
Pipeline-friendly CLI for processing Nessus scans
"""

import argparse
import sys
import json
import yaml
from pathlib import Path
from typing import Optional, Dict, Any
# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.nessus_to_llm import VulnProcessor


def load_config(config_path: str) -> Dict[str, Any]:
    """Load YAML or JSON config file"""
    if config_path == '-':
        # Read from stdin
        content = sys.stdin.read()
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError:
            return json.loads(content)
    
    with open(config_path, 'r') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            return yaml.safe_load(f)
        else:
            return json.load(f)


def apply_config_filters(processor: VulnProcessor, config: Dict[str, Any]) -> VulnProcessor:
    """Apply filters from config file"""
    filters = config.get('filters', [])
    
    for filter_def in filters:
        if 'exclude_cve' in filter_def:
            cve = filter_def['exclude_cve']
            processor.exclude_cve(cve)
        
        elif 'exclude' in filter_def:
            exc = filter_def['exclude']
            processor.exclude(
                ports=exc.get('ports'),
                min_cvss=exc.get('min_cvss'),
                max_cvss=exc.get('max_cvss'),
                severity=exc.get('severity'),
                except_if=exc.get('except_if')
            )
        
        elif 'include' in filter_def:
            inc = filter_def['include']
            if 'severity' in inc:
                processor.severity(inc['severity'])
            if 'min_cvss' in inc:
                processor.min_cvss(inc['min_cvss'])
            if 'max_cvss' in inc:
                processor.max_cvss(inc['max_cvss'])
            if 'ports' in inc:
                processor.ports(inc['ports'])
            if 'family' in inc:
                processor.family(inc['family'])
    
    # Apply flags
    for flag_def in config.get('flags', []):
        processor.flag(flag_def['name'], **flag_def.get('criteria', {}))
    
    return processor


def cmd_process(args):
    """Process command: Parse and filter Nessus file"""
    try:
        # Determine input source
        if args.input == '-':
            # Read from stdin and save to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.nessus', delete=False) as tf:
                tf.write(sys.stdin.read())
                input_file = tf.name
        else:
            input_file = args.input
        
        # Parse Nessus file
        if not args.silent:
            print(f"Parsing {input_file}...", file=sys.stderr)
        
        processor = VulnProcessor(input_file)
        
        # Apply config if provided
        if args.config:
            config = load_config(args.config)
            processor = apply_config_filters(processor, config)
        
        # Apply quick filters from CLI
        if args.severity:
            severity_levels = [int(s) for s in args.severity.split(',')]
            processor.severity(severity_levels)
        
        if args.exclude_cve:
            for cve in args.exclude_cve:
                processor.exclude_cve(cve)
        
        if args.exclude_port:
            # Parse except-family if provided
            except_if = None
            if args.except_family:
                families = args.except_family.split(',')
                except_if = {"family": families}
            
            processor.exclude(ports=args.exclude_port, except_if=except_if)
        
        if args.min_cvss:
            processor.min_cvss(args.min_cvss)
        
        # Get output
        if args.format == 'llm':
            output = processor.get_for_llm()
        else:
            output = processor.get()
        
        # Output
        output_json = json.dumps(output, indent=2 if not args.compact else None)
        
        if args.output and args.output != '-':
            with open(args.output, 'w') as f:
                f.write(output_json)
            if not args.silent:
                print(f"Output saved to {args.output}", file=sys.stderr)
        else:
            print(output_json)
        
        return 0
        
    except FileNotFoundError as e:
        print(f"ERROR: File not found: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"ERROR: Invalid input: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_extract(args):
    """Extract command: Extract specific severity levels"""
    try:
        # Load input
        if args.input == '-':
            data = json.load(sys.stdin)
        else:
            with open(args.input, 'r') as f:
                data = json.load(f)
        
        # Create processor from data
        processor = VulnProcessor()
        processor.data = data
        
        # Extract severity levels
        severity_levels = [int(s) for s in args.severity.split(',')]
        processor.severity(severity_levels)
        
        # Get output
        if args.format == 'llm':
            output = processor.get_for_llm()
        else:
            output = processor.get()
        
        # Output
        output_json = json.dumps(output, indent=2 if not args.compact else None)
        
        if args.output and args.output != '-':
            with open(args.output, 'w') as f:
                f.write(output_json)
        else:
            print(output_json)
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_merge(args):
    """Merge command: Merge processed results"""
    try:
        # Load all input files
        all_data = []
        for input_file in args.inputs:
            if input_file == '-':
                all_data.append(json.load(sys.stdin))
            else:
                with open(input_file, 'r') as f:
                    all_data.append(json.load(f))
        
        if len(all_data) == 0:
            print("ERROR: No input files provided", file=sys.stderr)
            return 1
        
        # Start with first file as base
        merged = all_data[0]
        
        # Merge additional data
        for data in all_data[1:]:
            # If it's a list (LLM format), merge into vulnerabilities
            if isinstance(data, list):
                # This is likely LLM-analyzed data
                # For now, just note it in metadata
                if 'llm_processed' not in merged:
                    merged['llm_processed'] = []
                merged['llm_processed'].append(data)
            
            # If it's a dict with vulnerabilities, merge them
            elif isinstance(data, dict) and 'vulnerabilities' in data:
                for level in ['critical', 'high', 'medium', 'low', 'info']:
                    if level in data['vulnerabilities']:
                        # Update by ID
                        existing_ids = {v['id']: v for v in merged['vulnerabilities'][level]}
                        for v in data['vulnerabilities'][level]:
                            if v['id'] in existing_ids:
                                # Update existing
                                existing_ids[v['id']].update(v)
                            else:
                                # Add new
                                merged['vulnerabilities'][level].append(v)
        
        # Output
        output_json = json.dumps(merged, indent=2 if not args.compact else None)
        
        if args.output and args.output != '-':
            with open(args.output, 'w') as f:
                f.write(output_json)
        else:
            print(output_json)
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_apply_config(args):
    """Apply config: Load and apply full config file"""
    try:
        config = load_config(args.config)
        
        # Get input file from config or args
        input_file = config.get('scan_file') or config.get('input')
        if not input_file:
            print("ERROR: No input file specified in config", file=sys.stderr)
            return 3
        
        # Process
        processor = VulnProcessor(input_file)
        processor = apply_config_filters(processor, config)
        
        # Get output file from config or use default
        output_file = config.get('output', 'output.json')
        
        # Check export format
        export_config = config.get('export', {})
        output_format = export_config.get('format', 'json')
        
        if output_format == 'llm':
            output = processor.get_for_llm()
        else:
            output = processor.get()
        
        # Save
        output_json = json.dumps(output, indent=2)
        with open(output_file, 'w') as f:
            f.write(output_json)
        
        if not args.silent:
            print(f"Processed and saved to {output_file}", file=sys.stderr)
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser(
        description='Vulnerability processing CLI - Pipeline-friendly Nessus scan processor'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Process command
    process_parser = subparsers.add_parser('process', help='Parse and filter Nessus file')
    process_parser.add_argument('input', help='Input Nessus file (use - for stdin)')
    process_parser.add_argument('--config', help='Config file (YAML/JSON) or - for stdin')
    process_parser.add_argument('--output', '-o', help='Output file (use - for stdout, default: stdout)')
    process_parser.add_argument('--format', choices=['json', 'llm'], default='json', 
                               help='Output format (default: json)')
    process_parser.add_argument('--severity', help='Filter by severity levels (e.g., 3,4)')
    process_parser.add_argument('--exclude-cve', action='append', help='Exclude CVE (can specify multiple times)')
    process_parser.add_argument('--exclude-port', type=int, action='append', help='Exclude port')
    process_parser.add_argument('--except-family', help='Exception for exclusion (comma-separated families)')
    process_parser.add_argument('--min-cvss', type=float, help='Minimum CVSS score')
    process_parser.add_argument('--silent', action='store_true', help='Silent mode (no progress output)')
    process_parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract specific severity levels')
    extract_parser.add_argument('input', help='Input JSON file (use - for stdin)')
    extract_parser.add_argument('--severity', required=True, help='Severity levels to extract (e.g., 3,4)')
    extract_parser.add_argument('--output', '-o', help='Output file (use - for stdout, default: stdout)')
    extract_parser.add_argument('--format', choices=['json', 'llm'], default='json',
                               help='Output format (default: json)')
    extract_parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    
    # Merge command
    merge_parser = subparsers.add_parser('merge', help='Merge processed results')
    merge_parser.add_argument('inputs', nargs='+', help='Input files to merge')
    merge_parser.add_argument('--output', '-o', help='Output file (use - for stdout, default: stdout)')
    merge_parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    
    # Apply config command
    apply_parser = subparsers.add_parser('apply-config', help='Apply full config file')
    apply_parser.add_argument('config', help='Config file (YAML/JSON)')
    apply_parser.add_argument('--silent', action='store_true', help='Silent mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Route to command handlers
    if args.command == 'process':
        return cmd_process(args)
    elif args.command == 'extract':
        return cmd_extract(args)
    elif args.command == 'merge':
        return cmd_merge(args)
    elif args.command == 'apply-config':
        return cmd_apply_config(args)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
