# src/builder.py
# Reads a target YAML config and builds baseline HTTP request objects
# One request object per endpoint + method combination

import sys
import os
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load_target(target_path):
    """
    Reads a target YAML file and returns it as a Python dict.
    Exits cleanly if the file is missing or malformed.
    """
    if not os.path.exists(target_path):
        print(f"[BUILDER][ERROR] Target file not found: {target_path}")
        sys.exit(1)

    with open(target_path, 'r') as f:
        try:
            target = yaml.safe_load(f)
            print(f"[BUILDER] Loaded target: {target.get('name', 'unknown')}")
            print(f"[BUILDER] Base URL: {target.get('base_url')}")
            return target
        except yaml.YAMLError as e:
            print(f"[BUILDER][ERROR] Could not parse target file: {e}")
            sys.exit(1)


def build_requests(target):
    """
    Takes a loaded target config and returns a list of
    baseline request objects — one per endpoint/method combo.

    Each request object is a dict with:
      - method:   HTTP method (GET, POST, etc.)
      - url:      full URL including base
      - headers:  headers from config
      - params:   query string parameters (for GET)
      - body:     request body (for POST/PUT/PATCH)
      - endpoint: the path string (for reporting)
      - param_defs: list of param definitions for the fuzzer
    """
    base_url  = target.get('base_url', '').rstrip('/')
    headers   = target.get('headers', {})
    endpoints = target.get('endpoints', [])
    requests_list = []

    for endpoint in endpoints:
        path       = endpoint.get('path', '/')
        methods    = endpoint.get('methods', ['GET'])
        param_defs = endpoint.get('params', [])

        url = base_url + path

        for method in methods:
            method = method.upper()

            # Separate params into query params and body params
            query_params = {}
            body_params  = {}

            for param in param_defs:
                param_name    = param.get('name')
                param_type    = param.get('type', 'query')
                param_default = param.get('default', '')

                if param_type == 'query':
                    query_params[param_name] = param_default
                elif param_type == 'body':
                    body_params[param_name] = param_default

            # For GET requests body params don't apply
            # For POST/PUT/PATCH query params still go in URL
            if method == 'GET':
                body = {}
            else:
                body = body_params

            request_obj = {
                'method':     method,
                'url':        url,
                'headers':    dict(headers),
                'params':     query_params,
                'body':       body,
                'endpoint':   path,
                'param_defs': param_defs,
            }

            requests_list.append(request_obj)
            print(f"[BUILDER] Built: {method:<6} {url}")

    print(f"[BUILDER] Total baseline requests: {len(requests_list)}")
    return requests_list


def get_all_param_names(request_obj):
    """
    Returns a flat list of all parameter names for a request.
    Used by the fuzzer to know what to mutate.
    """
    names = []
    names.extend(request_obj.get('params', {}).keys())
    names.extend(request_obj.get('body', {}).keys())
    return names
