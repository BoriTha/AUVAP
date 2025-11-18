#!/usr/bin/env python3
"""
End-to-End Vulnerability Processing Pipeline
Parse Nessus/Nmap → Classify with CWE/MITRE ATT&CK → Output RL-Ready JSON

Usage:
    # Nessus workflow (existing)
    python scripts/parse_and_classify.py <nessus_file> [output_file]
    
    # Nmap workflows (new)
    python scripts/parse_and_classify.py --scan-nmap --target <IP> [output_file]
    python scripts/parse_and_classify.py --nmap-xml <nmap_file> [output_file]

Example:
    python scripts/parse_and_classify.py data/input/scan.nessus data/output/rl_ready.json
    python scripts/parse_and_classify.py --scan-nmap --target 192.168.79.128 data/output/rl_ready.json
"""

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.nessus_to_llm import VulnProcessor  # type: ignore
from classifier.vulnerability_classifier import VulnerabilityClassifier  # type: ignore
from apfa_agent.core.nmap_scanner import SmartNmapScanner  # type: ignore
from apfa_agent.utils.scan_adapter import convert_nmap_for_classifier  # type: ignore
from apfa_agent.utils.nmap_utils import detect_scan_type  # type: ignore


def parse_and_classify(
    nessus_file: str,
    output_file: str,
    severity_filter = None,
    min_cvss = None,
    enable_rag: bool = False,
    verbose: bool = True
):
    """
    Complete pipeline: Parse Nessus → Filter → Classify → Save
    
    Args:
        nessus_file: Path to .nessus XML file
        output_file: Path to save RL-ready JSON output
        severity_filter: List of severity levels to include (e.g., [3, 4])
        min_cvss: Minimum CVSS score filter
        enable_rag: Enable RAG-based classification (requires API key)
        verbose: Print progress information
    """
    if verbose:
        print("╔" + "="*58 + "╗")
        print("║" + " "*10 + "VULNERABILITY PROCESSING PIPELINE" + " "*14 + "║")
        print("╚" + "="*58 + "╝")
        print()
    
    # Step 1: Parse Nessus file
    if verbose:
        print(f"[1/4] Parsing Nessus file: {nessus_file}")
    
    try:
        processor = VulnProcessor(nessus_file)
    except Exception as e:
        print(f"❌ Error parsing Nessus file: {e}")
        sys.exit(1)
    
    # Apply filters if specified
    if severity_filter:
        processor.severity(severity_filter)
    if min_cvss:
        processor.min_cvss(min_cvss)
    
    # Get filtered vulnerabilities in LLM format
    vulnerabilities = processor.get_for_llm()
    
    if verbose:
        print(f"   ✓ Parsed {len(vulnerabilities)} vulnerabilities")
        scan_meta = processor.data.get("scan_meta", {})
        print(f"   ✓ Scan date: {scan_meta.get('scan_date', 'Unknown')}")
        print(f"   ✓ Severity breakdown: {scan_meta.get('by_severity', {})}")
        print()
    
    # Step 2: Classify vulnerabilities
    if verbose:
        print(f"[2/4] Classifying vulnerabilities with CWE/MITRE ATT&CK...")
        print(f"   Mode: {'hybrid (pattern + CVE lookup + RAG)' if enable_rag else 'hybrid (pattern + CVE lookup)'}")
        print()
    
    classifier = VulnerabilityClassifier(mode="hybrid", enable_rag=enable_rag)
    classified = classifier.classify_batch(vulnerabilities)
    
    if verbose:
        print(f"   ✓ Classified {len(classified)} vulnerabilities")
        stats = classifier.get_stats()
        print(f"   ✓ Pattern matches: {stats['pattern_matches']}")
        print(f"   ✓ CVE lookups: {stats['cve_lookups']}")
        print(f"   ✓ RAG classifications: {stats['rag_classifications']}")
        print(f"   ✓ Generic fallbacks: {stats['fallback_generic']}")
        print()
    
    # Step 3: Enrich for RL agent
    if verbose:
        print(f"[3/4] Enriching data for RL agent consumption...")
    
    # Calculate summary statistics
    total_vulns = len(classified)
    high_priority = sum(1 for v in classified if v["classification"]["priority_score"] >= 8.0)
    with_exploits = sum(1 for v in classified 
                       if v["classification"]["exploitation_assessment"].get("publicly_available_exploit"))
    
    # Create RL-ready output with metadata
    rl_ready_output = {
        "metadata": {
            "source_file": nessus_file,
            "processed_at": datetime.utcnow().isoformat() + "Z",
            "classifier_version": classifier.VERSION,
            "total_vulnerabilities": total_vulns,
            "high_priority_count": high_priority,
            "public_exploits_available": with_exploits,
            "filters_applied": {
                "severity": severity_filter if severity_filter else "all",
                "min_cvss": min_cvss if min_cvss else "none"
            }
        },
        "vulnerabilities": classified,
        "rl_agent_summary": {
            "prioritized_targets": sorted(
                classified,
                key=lambda x: x["classification"]["priority_score"],
                reverse=True
            )[:10],  # Top 10 targets
            "attack_types": list(set(
                v["classification"]["rl_agent_hints"]["attack_type"]
                for v in classified
            )),
            "required_tools": list(set(
                tool
                for v in classified
                for tool in v["classification"]["rl_agent_hints"]["suggested_tools"]
            ))
        }
    }
    
    if verbose:
        print(f"   ✓ Total vulnerabilities: {total_vulns}")
        print(f"   ✓ High priority (≥8.0): {high_priority}")
        print(f"   ✓ Public exploits available: {with_exploits}")
        print(f"   ✓ Unique attack types: {len(rl_ready_output['rl_agent_summary']['attack_types'])}")
        print(f"   ✓ Required tools: {len(rl_ready_output['rl_agent_summary']['required_tools'])}")
        print()
    
    # Step 4: Save output
    if verbose:
        print(f"[4/4] Saving RL-ready output to: {output_file}")
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(rl_ready_output, f, indent=2)
    
    if verbose:
        file_size = output_path.stat().st_size / 1024  # KB
        print(f"   ✓ Saved {file_size:.1f} KB")
        print()
        print("="*60)
        print("✅ Pipeline completed successfully!")
        print("="*60)
        print()
        print("Next steps:")
        print(f"1. Review the output: {output_file}")
        print("2. Load into your RL agent for attack simulation")
        print("3. Use the prioritized_targets for efficient pentesting")
        print()
    
    return rl_ready_output


def main():
    parser = argparse.ArgumentParser(
        description="End-to-end vulnerability processing: Parse → Classify → RL-Ready Output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python scripts/parse_and_classify.py data/input/scan.nessus data/output/rl_ready.json
  
  # Filter critical/high only
  python scripts/parse_and_classify.py data/input/scan.nessus data/output/critical.json --severity 3 4
  
  # Filter by CVSS score
  python scripts/parse_and_classify.py data/input/scan.nessus data/output/high_cvss.json --min-cvss 7.0
  
  # Enable RAG mode (requires OPENROUTER_API_KEY in .env)
  python scripts/parse_and_classify.py data/input/scan.nessus data/output/rl_ready.json --enable-rag
  
  # Quiet mode
  python scripts/parse_and_classify.py data/input/scan.nessus data/output/rl_ready.json --quiet
        """
    )
    
    parser.add_argument("nessus_file", help="Path to .nessus XML file")
    parser.add_argument("output_file", nargs="?", default="data/output/rl_ready.json",
                       help="Path to save RL-ready JSON output (default: data/output/rl_ready.json)")
    parser.add_argument("--severity", type=int, nargs="+", choices=[0, 1, 2, 3, 4],
                       help="Filter by severity levels (0=info, 1=low, 2=medium, 3=high, 4=critical)")
    parser.add_argument("--min-cvss", type=float,
                       help="Minimum CVSS score filter (0.0-10.0)")
    parser.add_argument("--enable-rag", action="store_true",
                       help="Enable RAG-based classification (requires API key)")
    parser.add_argument("--quiet", "-q", action="store_true",
                       help="Suppress progress output")
    
    args = parser.parse_args()
    
    # Validate inputs
    if not Path(args.nessus_file).exists():
        print(f"❌ Error: Nessus file not found: {args.nessus_file}")
        sys.exit(1)
    
    if args.min_cvss and (args.min_cvss < 0 or args.min_cvss > 10):
        print(f"❌ Error: Invalid CVSS score. Must be between 0.0 and 10.0")
        sys.exit(1)
    
    # Run pipeline
    try:
        parse_and_classify(
            nessus_file=args.nessus_file,
            output_file=args.output_file,
            severity_filter=args.severity,
            min_cvss=args.min_cvss,
            enable_rag=args.enable_rag,
            verbose=not args.quiet
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Pipeline interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
