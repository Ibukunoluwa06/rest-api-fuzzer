# src/runner.py
# Main entry point — wires all fuzzer stages together
# Usage: python3 src/runner.py --target targets/example_target.yaml

import sys
import os
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.builder  import load_target, build_requests
from src.fuzzer   import load_all_wordlists, fuzz
from src.analyzer import analyze
from src.reporter import generate_report


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def parse_args():
    """
    Parses command line arguments.
    Lets you control the fuzzer without editing any code.
    """
    parser = argparse.ArgumentParser(
        description='REST API Fuzzer — automated API security testing'
    )
    parser.add_argument(
        '--target',
        required=True,
        help='Path to target YAML file (e.g. targets/example_target.yaml)'
    )
    parser.add_argument(
        '--strategies',
        nargs='+',
        default=['sql', 'xss', 'traversal', 'params', 'methods', 'boundary'],
        choices=['sql', 'xss', 'traversal', 'params', 'methods', 'boundary'],
        help='Fuzzing strategies to run (default: all)'
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=0.1,
        help='Delay between requests in seconds (default: 0.1)'
    )
    parser.add_argument(
        '--output',
        default='./output',
        help='Directory to save report (default: ./output)'
    )
    parser.add_argument(
        '--endpoints',
        nargs='+',
        default=None,
        help='Only fuzz specific endpoints e.g. --endpoints /login /users'
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run(args):
    """
    Full fuzzer pipeline:
    1. Load target config
    2. Build baseline requests
    3. Load wordlists
    4. Generate fuzz variants
    5. Send and analyze
    6. Generate report
    """
    start_time = time.time()

    print()
    print("=" * 60)
    print("  REST API FUZZER — STARTING")
    print("=" * 60)
    print(f"  Target     : {args.target}")
    print(f"  Strategies : {', '.join(args.strategies)}")
    print(f"  Delay      : {args.delay}s between requests")
    print(f"  Output     : {args.output}")
    print("=" * 60)

    # ---------------------
    # Stage 1: Load target
    # ---------------------
    print("\n[STAGE 1] Loading target config...")
    target = load_target(args.target)
    target_name = target.get('name', 'unknown')

    # Filter endpoints if --endpoints flag was used
    if args.endpoints:
        original_count = len(target.get('endpoints', []))
        target['endpoints'] = [
            e for e in target.get('endpoints', [])
            if e.get('path') in args.endpoints
        ]
        filtered_count = len(target['endpoints'])
        print(f"[STAGE 1] Filtered to {filtered_count} of "
              f"{original_count} endpoints")

    # ---------------------
    # Stage 2: Build requests
    # ---------------------
    print("\n[STAGE 2] Building baseline requests...")
    baseline_requests = build_requests(target)

    if not baseline_requests:
        print("[ERROR] No requests built — check your target config.")
        sys.exit(1)

    # ---------------------
    # Stage 3: Load wordlists
    # ---------------------
    print("\n[STAGE 3] Loading wordlists...")
    wordlists = load_all_wordlists()

    # ---------------------
    # Stage 4: Generate variants
    # ---------------------
    print("\n[STAGE 4] Generating fuzz variants...")
    variants = fuzz(baseline_requests, wordlists, args.strategies)

    if not variants:
        print("[ERROR] No variants generated — nothing to fuzz.")
        sys.exit(1)

    # ---------------------
    # Stage 5: Analyze
    # ---------------------
    print("\n[STAGE 5] Sending requests and analyzing responses...")
    print(f"[WARNING] Only run this against systems you own "
          f"or have permission to test.\n")

    results, findings = analyze(variants, delay=args.delay)

    # ---------------------
    # Stage 6: Report
    # ---------------------
    duration = time.time() - start_time

    print("\n[STAGE 6] Generating report...")
    report_path = generate_report(
        findings    = findings,
        results     = results,
        target_name = target_name,
        duration    = duration,
        output_dir  = args.output,
    )

    print(f"\n[RUNNER] Finished in {duration:.1f}s")
    print(f"[RUNNER] Report saved to: {report_path}")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    args = parse_args()
    run(args)
