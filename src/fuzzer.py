# src/fuzzer.py
# Takes baseline requests and produces mutated variants
# using payloads from wordlists

import os
import sys
import copy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Wordlist loader
# ---------------------------------------------------------------------------

WORDLIST_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'wordlists'
)


def load_wordlist(filename):
    """
    Loads a wordlist file and returns a list of payloads.
    Skips empty lines and comment lines starting with #.
    """
    filepath = os.path.join(WORDLIST_DIR, filename)

    if not os.path.exists(filepath):
        print(f"[FUZZER][WARN] Wordlist not found: {filepath}")
        return []

    with open(filepath, 'r', errors='replace') as f:
        payloads = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith('#')
        ]

    print(f"[FUZZER] Loaded {len(payloads):>3} payloads from {filename}")
    return payloads


def load_all_wordlists():
    """
    Loads all wordlists and returns them as a named dict.
    """
    return {
        'sql':       load_wordlist('sql_injection.txt'),
        'xss':       load_wordlist('xss.txt'),
        'traversal': load_wordlist('path_traversal.txt'),
        'params':    load_wordlist('common_params.txt'),
    }


# ---------------------------------------------------------------------------
# Mutation strategies
# Each strategy takes a baseline request and returns a list
# of mutated request variants
# ---------------------------------------------------------------------------

def mutate_param_values(request, payloads, strategy_name):
    """
    Strategy 1: Replace each parameter value with each payload.
    If a request has 2 params and 30 payloads, produces 60 variants.
    """
    variants = []

    # Mutate query params
    for param_name in request.get('params', {}):
        for payload in payloads:
            variant = copy.deepcopy(request)
            variant['params'][param_name] = payload
            variant['fuzz_info'] = {
                'strategy':  strategy_name,
                'location':  'query_param',
                'param':     param_name,
                'payload':   payload,
            }
            variants.append(variant)

    # Mutate body params
    for param_name in request.get('body', {}):
        for payload in payloads:
            variant = copy.deepcopy(request)
            variant['body'][param_name] = payload
            variant['fuzz_info'] = {
                'strategy':  strategy_name,
                'location':  'body_param',
                'param':     param_name,
                'payload':   payload,
            }
            variants.append(variant)

    return variants


def inject_extra_params(request, param_names):
    """
    Strategy 2: Inject extra parameter names the API didn't advertise.
    Looks for hidden params like debug=true, admin=1, role=admin.
    """
    variants = []

    suspicious_values = ['true', '1', 'admin', 'yes', '../etc/passwd', 'null']

    for param_name in param_names:
        for value in suspicious_values:
            # Try as query param
            variant = copy.deepcopy(request)
            variant['params'][param_name] = value
            variant['fuzz_info'] = {
                'strategy': 'extra_param_injection',
                'location': 'query_param',
                'param':    param_name,
                'payload':  value,
            }
            variants.append(variant)

    return variants


def mutate_method(request):
    """
    Strategy 3: Try unexpected HTTP methods on each endpoint.
    Some APIs forget to restrict methods — DELETE on a GET endpoint,
    PUT where only POST is expected, etc.
    """
    variants  = []
    original  = request['method']
    all_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']
    other_methods = [m for m in all_methods if m != original]

    for method in other_methods:
        variant = copy.deepcopy(request)
        variant['method'] = method
        variant['fuzz_info'] = {
            'strategy': 'method_tamper',
            'location': 'method',
            'param':    'HTTP method',
            'payload':  method,
        }
        variants.append(variant)

    return variants


def mutate_boundary_values(request):
    """
    Strategy 4: Test boundary and edge case values.
    Empty strings, nulls, huge numbers, negative values,
    very long strings — these often trigger unexpected behaviour.
    """
    boundary_payloads = [
        '',                          # empty string
        ' ',                         # whitespace
        'null',                      # string null
        'undefined',                 # JS undefined
        '0',                         # zero
        '-1',                        # negative
        '99999999999999999999',      # huge number
        'A' * 1000,                  # very long string
        'A' * 10000,                 # extremely long string
        '\x00',                      # null byte
        '\n\r',                      # newline chars
        '{}',                        # empty JSON object
        '[]',                        # empty JSON array
        'true',                      # boolean string
        'false',                     # boolean string
        '<>',                        # angle brackets
        '../../../../',              # quick traversal
        "' OR '1'='1",              # quick SQL
    ]

    return mutate_param_values(request, boundary_payloads, 'boundary_values')


# ---------------------------------------------------------------------------
# Main fuzzer
# ---------------------------------------------------------------------------

def fuzz(requests_list, wordlists, strategies=None):
    """
    Takes a list of baseline requests and returns all mutated variants.

    strategies controls which mutation types to run:
    - 'sql'       : SQL injection payloads
    - 'xss'       : XSS payloads
    - 'traversal' : Path traversal payloads
    - 'params'    : Hidden parameter injection
    - 'methods'   : HTTP method tampering
    - 'boundary'  : Boundary and edge case values

    If strategies is None all are run.
    """
    if strategies is None:
        strategies = ['sql', 'xss', 'traversal', 'params', 'methods', 'boundary']

    all_variants = []

    for request in requests_list:
        endpoint = request.get('endpoint', '?')
        method   = request.get('method', '?')
        print(f"\n[FUZZER] Generating variants for {method} {endpoint}")

        # Always include the baseline request first
        baseline = copy.deepcopy(request)
        baseline['fuzz_info'] = {
            'strategy': 'baseline',
            'location': 'none',
            'param':    'none',
            'payload':  'none',
        }
        all_variants.append(baseline)

        count_before = len(all_variants)

        # Run each strategy
        if 'sql' in strategies:
            variants = mutate_param_values(
                request, wordlists['sql'], 'sql_injection'
            )
            all_variants.extend(variants)

        if 'xss' in strategies:
            variants = mutate_param_values(
                request, wordlists['xss'], 'xss'
            )
            all_variants.extend(variants)

        if 'traversal' in strategies:
            variants = mutate_param_values(
                request, wordlists['traversal'], 'path_traversal'
            )
            all_variants.extend(variants)

        if 'params' in strategies:
            variants = inject_extra_params(
                request, wordlists['params']
            )
            all_variants.extend(variants)

        if 'methods' in strategies:
            variants = mutate_method(request)
            all_variants.extend(variants)

        if 'boundary' in strategies:
            variants = mutate_boundary_values(request)
            all_variants.extend(variants)

        count_after  = len(all_variants)
        new_variants = count_after - count_before
        print(f"[FUZZER] Generated {new_variants} variants "
              f"for {method} {endpoint}")

    print(f"\n[FUZZER] Total variants to send: {len(all_variants)}")
    return all_variants
