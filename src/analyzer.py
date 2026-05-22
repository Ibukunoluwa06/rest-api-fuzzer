# src/analyzer.py
# Sends mutated requests and analyzes responses for vulnerabilities
# Detects: 500 errors, info leakage, slow responses, anomalous sizes

import sys
import os
import time
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Detection rules
# These strings in a response body indicate information leakage
# ---------------------------------------------------------------------------
LEAKAGE_PATTERNS = [
    # Database errors
    'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
    'syntax error', 'sql error', 'database error',
    'ORA-', 'PG::', 'SQLSTATE',

    # Stack traces
    'traceback', 'stack trace', 'at line',
    'exception', 'error in', 'undefined method',
    'nullpointerexception', 'indexoutofbounds',

    # Credentials and secrets
    'password', 'passwd', 'secret', 'api_key',
    'private_key', 'access_token', 'connection string',
    'jdbc:', 'mongodb://', 'mysql://', 'postgres://',

    # Server info
    'apache', 'nginx', 'iis', 'tomcat',
    'php/', 'python/', 'ruby/', 'java/',
    'debug', 'internal server',
]

# Response time threshold in seconds
# Responses slower than this are flagged as potential DoS
SLOW_RESPONSE_THRESHOLD = 1.5

# Response size anomaly threshold
# If a response is X times bigger or smaller than baseline, flag it
SIZE_ANOMALY_FACTOR = 5


# ---------------------------------------------------------------------------
# Single request sender
# ---------------------------------------------------------------------------

def send_request(variant, timeout=10):
    """
    Sends a single HTTP request and returns a result dict.
    Never raises exceptions — always returns a result even on error.
    """
    method   = variant.get('method', 'GET')
    url      = variant.get('url', '')
    headers  = variant.get('headers', {})
    params   = variant.get('params', {})
    body     = variant.get('body', {})
    fuzz_info = variant.get('fuzz_info', {})

    start_time = time.time()

    try:
        response = requests.request(
            method  = method,
            url     = url,
            headers = headers,
            params  = params,
            json    = body if body else None,
            timeout = timeout,
            allow_redirects = True,
        )
        elapsed = time.time() - start_time

        return {
            'status_code':   response.status_code,
            'response_time': round(elapsed, 3),
            'body':          response.text,
            'body_size':     len(response.text),
            'headers':       dict(response.headers),
            'fuzz_info':     fuzz_info,
            'request':       {
                'method':  method,
                'url':     url,
                'params':  params,
                'body':    body,
            },
            'error': None,
        }

    except requests.exceptions.ConnectionError:
        return _error_result(
            fuzz_info, method, url, params, body,
            'Connection refused — is the target server running?'
        )
    except requests.exceptions.Timeout:
        return _error_result(
            fuzz_info, method, url, params, body,
            f'Request timed out after {timeout}s'
        )
    except Exception as e:
        return _error_result(
            fuzz_info, method, url, params, body,
            str(e)
        )


def _error_result(fuzz_info, method, url, params, body, error_msg):
    """Builds a consistent result dict for failed requests."""
    return {
        'status_code':   0,
        'response_time': 0,
        'body':          '',
        'body_size':     0,
        'headers':       {},
        'fuzz_info':     fuzz_info,
        'request':       {
            'method': method,
            'url':    url,
            'params': params,
            'body':   body,
        },
        'error': error_msg,
    }


# ---------------------------------------------------------------------------
# Detection checks
# Each check takes a result and baseline and returns a finding or None
# ---------------------------------------------------------------------------

def check_server_error(result):
    """
    Flags any 5xx response — server errors caused by bad input
    usually indicate the API is not handling input safely.
    """
    if result['status_code'] >= 500:
        return {
            'type':        'server_error',
            'severity':    'HIGH',
            'title':       f"Server error {result['status_code']} triggered",
            'description': (
                f"The payload caused a {result['status_code']} response. "
                f"This suggests unhandled input reaching backend logic."
            ),
            'evidence':    result['body'][:300],
        }
    return None


def check_info_leakage(result):
    """
    Scans the response body for sensitive strings —
    database errors, stack traces, credentials, server info.
    """
    body_lower = result['body'].lower()
    found      = []

    for pattern in LEAKAGE_PATTERNS:
        if pattern.lower() in body_lower:
            found.append(pattern)

    if found:
        return {
            'type':        'info_leakage',
            'severity':    'HIGH',
            'title':       'Sensitive information leaked in response',
            'description': (
                f"Response contains sensitive keywords: "
                f"{', '.join(found[:5])}"
            ),
            'evidence':    result['body'][:300],
        }
    return None


def check_slow_response(result):
    """
    Flags responses that took longer than the threshold.
    Slow responses on large inputs suggest DoS vulnerability.
    """
    if result['response_time'] > SLOW_RESPONSE_THRESHOLD:
        return {
            'type':        'slow_response',
            'severity':    'MEDIUM',
            'title':       f"Slow response: {result['response_time']}s",
            'description': (
                f"Response took {result['response_time']}s — "
                f"above threshold of {SLOW_RESPONSE_THRESHOLD}s. "
                f"Possible DoS vulnerability on large input."
            ),
            'evidence':    f"Response time: {result['response_time']}s",
        }
    return None


def check_size_anomaly(result, baseline_size):
    """
    Flags responses much larger or smaller than the baseline.
    Large responses may indicate data exfiltration.
    Small responses may indicate access control bypass.
    """
    if baseline_size == 0:
        return None

    ratio = result['body_size'] / baseline_size

    if ratio > SIZE_ANOMALY_FACTOR:
        return {
            'type':        'size_anomaly',
            'severity':    'MEDIUM',
            'title':       'Unusually large response',
            'description': (
                f"Response is {ratio:.1f}x larger than baseline "
                f"({result['body_size']} vs {baseline_size} bytes). "
                f"Possible data exfiltration."
            ),
            'evidence': result['body'][:300],
        }
    return None


def check_method_not_restricted(result, baseline_status):
    """
    Flags when an unexpected HTTP method succeeds (2xx response)
    on an endpoint that normally returns 4xx for that method.
    """
    fuzz_info = result.get('fuzz_info', {})
    if fuzz_info.get('strategy') != 'method_tamper':
        return None

    if result['status_code'] < 300:
        return {
            'type':        'unrestricted_method',
            'severity':    'MEDIUM',
            'title':       f"Unexpected method accepted: {result['request']['method']}",
            'description': (
                f"The server accepted an unexpected HTTP method "
                f"with status {result['status_code']}."
            ),
            'evidence': f"Method: {result['request']['method']} → {result['status_code']}",
        }
    return None


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze(variants, delay=0.1):
    """
    Sends all variants and collects findings.

    delay = seconds to wait between requests (be polite to the server)

    Returns:
      - results:  all raw results
      - findings: all detected vulnerabilities
    """
    results  = []
    findings = []

    total        = len(variants)
    baseline_size = 0
    baseline_status = 200

    print(f"\n[ANALYZER] Sending {total} requests...")
    print(f"[ANALYZER] Delay between requests: {delay}s")
    print()

    for i, variant in enumerate(variants):
        fuzz_info = variant.get('fuzz_info', {})
        strategy  = fuzz_info.get('strategy', 'unknown')

        # Send the request
        result = send_request(variant)
        results.append(result)

        # Use the baseline result to calibrate detectors
        if strategy == 'baseline':
            baseline_size   = result['body_size']
            baseline_status = result['status_code']
            status_icon     = '✓'
            print(f"  [{i+1:>4}/{total}] {status_icon} BASELINE "
                  f"{result['request']['method']:<6} "
                  f"{result['request']['url']} "
                  f"→ {result['status_code']} "
                  f"({result['response_time']}s)")
            time.sleep(delay)
            continue

        # Skip connection errors silently
        if result['error']:
            time.sleep(delay)
            continue

        # Run all detection checks
        variant_findings = []

        checks = [
            check_server_error(result),
            check_info_leakage(result),
            check_slow_response(result),
            check_size_anomaly(result, baseline_size),
            check_method_not_restricted(result, baseline_status),
        ]

        for check in checks:
            if check:
                check['request']  = result['request']
                check['fuzz_info'] = fuzz_info
                variant_findings.append(check)
                findings.append(check)

        # Print progress
        has_finding = len(variant_findings) > 0
        icon        = '!' if has_finding else ' '
        param       = fuzz_info.get('param', '')[:12]
        payload     = str(fuzz_info.get('payload', ''))[:15]

        print(f"  [{i+1:>4}/{total}] {icon} "
              f"{result['request']['method']:<6} "
              f"{result['status_code']} "
              f"({result['response_time']:>5}s) "
              f"param={param:<12} "
              f"payload={payload}")

        time.sleep(delay)

    print(f"\n[ANALYZER] Done. "
          f"{len(results)} requests sent, "
          f"{len(findings)} findings.")

    return results, findings
