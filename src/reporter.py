# src/reporter.py
# Turns raw findings into a colour-coded terminal report
# and saves a structured JSON report to disk

import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorama import init, Fore, Style
init(autoreset=True)


# ---------------------------------------------------------------------------
# Severity colours
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    'HIGH':   Fore.RED    + Style.BRIGHT,
    'MEDIUM': Fore.YELLOW + Style.BRIGHT,
    'LOW':    Fore.CYAN   + Style.BRIGHT,
    'INFO':   Fore.WHITE,
}

SEVERITY_ORDER = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}


# ---------------------------------------------------------------------------
# Terminal report
# ---------------------------------------------------------------------------

def print_banner(target_name, total_requests, total_findings, duration):
    """Prints the report header."""
    print()
    print(Fore.WHITE + Style.BRIGHT + "=" * 60)
    print(Fore.WHITE + Style.BRIGHT + "  REST API FUZZER — RESULTS")
    print(Fore.WHITE + Style.BRIGHT + "=" * 60)
    print(f"  Target   : {target_name}")
    print(f"  Requests : {total_requests}")
    print(f"  Duration : {duration:.1f}s")
    print(f"  Findings : {total_findings}")
    print(Fore.WHITE + Style.BRIGHT + "=" * 60)
    print()


def print_findings(findings):
    """
    Prints all findings sorted by severity.
    HIGH first, then MEDIUM, then LOW.
    """
    if not findings:
        print(Fore.GREEN + Style.BRIGHT + "  ✓ No vulnerabilities found.")
        print()
        return

    # Sort by severity
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'INFO'), 99)
    )

    # Count by severity
    counts = {}
    for f in findings:
        sev = f.get('severity', 'INFO')
        counts[sev] = counts.get(sev, 0) + 1

    # Print severity summary bar
    print("  Severity breakdown:")
    for sev in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, '')
            bar   = '█' * count
            print(f"    {color}{sev:<8}{Style.RESET_ALL} "
                  f"{bar} {count}")
    print()

    # Print each finding
    print("  Findings:")
    print()
    for i, finding in enumerate(sorted_findings, 1):
        sev      = finding.get('severity', 'INFO')
        color    = SEVERITY_COLORS.get(sev, '')
        title    = finding.get('title', 'Unknown')
        desc     = finding.get('description', '')
        evidence = finding.get('evidence', '')
        req      = finding.get('request', {})
        fuzz     = finding.get('fuzz_info', {})

        print(f"  {color}[{sev}] Finding #{i}: {title}{Style.RESET_ALL}")
        print(f"  {'─' * 56}")
        print(f"  Description : {desc}")
        print(f"  Endpoint    : {req.get('method','?')} {req.get('url','?')}")
        print(f"  Strategy    : {fuzz.get('strategy','?')}")
        print(f"  Parameter   : {fuzz.get('param','?')}")
        print(f"  Payload     : {str(fuzz.get('payload','?'))[:60]}")
        if evidence:
            print(f"  Evidence    : {evidence[:120]}")
        print()


def print_summary(findings, duration):
    """Prints the final summary line."""
    high   = sum(1 for f in findings if f.get('severity') == 'HIGH')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    low    = sum(1 for f in findings if f.get('severity') == 'LOW')

    print(Fore.WHITE + Style.BRIGHT + "=" * 60)
    print("  SUMMARY")
    print(Fore.WHITE + Style.BRIGHT + "=" * 60)

    if high > 0:
        print(Fore.RED + Style.BRIGHT +
              f"  ✗ {high} HIGH severity finding(s) — immediate attention needed")
    if medium > 0:
        print(Fore.YELLOW + Style.BRIGHT +
              f"  ⚠ {medium} MEDIUM severity finding(s) — review recommended")
    if low > 0:
        print(Fore.CYAN + Style.BRIGHT +
              f"  ℹ {low} LOW severity finding(s) — informational")
    if not findings:
        print(Fore.GREEN + Style.BRIGHT +
              "  ✓ API appears clean — no issues detected")

    print(f"\n  Completed in {duration:.1f}s")
    print(Fore.WHITE + Style.BRIGHT + "=" * 60)
    print()


# ---------------------------------------------------------------------------
# JSON report writer
# ---------------------------------------------------------------------------

def save_report(findings, results, target_name,
                total_requests, duration, output_dir='./output'):
    """
    Saves a full structured JSON report to disk.
    Returns the path to the saved file.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Build timestamp for filename
    now       = datetime.now(timezone.utc)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    filename  = f"report_{target_name}_{timestamp}.json"
    filepath  = os.path.join(output_dir, filename)

    # Deduplicate findings by type + endpoint + param
    seen     = set()
    unique   = []
    for f in findings:
        key = (
            f.get('type'),
            f.get('request', {}).get('url'),
            f.get('fuzz_info', {}).get('param'),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Count by severity
    severity_counts = {}
    for f in unique:
        sev = f.get('severity', 'INFO')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        'meta': {
            'target':          target_name,
            'generated_at':    now.isoformat(),
            'total_requests':  total_requests,
            'duration_seconds': round(duration, 2),
            'total_findings':  len(unique),
            'severity_counts': severity_counts,
        },
        'findings': unique,
        'stats': {
            'total_variants_sent': total_requests,
            'findings_by_type': _count_by_type(unique),
        }
    }

    with open(filepath, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[REPORTER] Report saved: {filepath}")
    return filepath


def _count_by_type(findings):
    """Counts findings grouped by type."""
    counts = {}
    for f in findings:
        t = f.get('type', 'unknown')
        counts[t] = counts.get(t, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Main reporter — call this from runner.py
# ---------------------------------------------------------------------------

def generate_report(findings, results, target_name,
                    duration, output_dir='./output'):
    """
    Full report pipeline:
    1. Print colour-coded terminal output
    2. Save JSON file to disk
    """
    total_requests = len(results)

    # Terminal output
    print_banner(target_name, total_requests, len(findings), duration)
    print_findings(findings)
    print_summary(findings, duration)

    # Save to disk
    filepath = save_report(
        findings, results, target_name,
        total_requests, duration, output_dir
    )

    return filepath
