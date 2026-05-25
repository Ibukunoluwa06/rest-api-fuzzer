# REST API Fuzzer

A Python-based REST API security fuzzer that automatically sends
mutated HTTP requests to discover vulnerabilities including SQL injection,
XSS, information leakage, slow responses, and unrestricted HTTP methods.

Built as a hands-on introduction to API security testing and
penetration testing concepts using Python.

---

## Results on built-in mock server
- 2291 requests sent
- 291 findings detected (218 HIGH, 73 MEDIUM)
- Detected: SQL injection responses, credential leakage, DoS via large input

---

## Features
- SQL injection, XSS, path traversal, and boundary value fuzzing
- Hidden parameter injection using common param wordlists
- HTTP method tampering detection
- Information leakage detection (stack traces, DB strings, credentials)
- Slow response / DoS detection
- Colour-coded terminal output and JSON report saved to disk
- YAML-based target config — no code changes needed
- Includes a deliberately vulnerable mock server for safe local testing

---

## Architecture
