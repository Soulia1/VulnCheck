#!/usr/bin/env python3
"""
VulnCheck Python Static Analysis Engine
Detects: Command Injection, Code Injection, SQL Injection,
         Insecure Deserialization, Path Traversal,
         Hardcoded Secret, Insecure Randomness
Output: JSON to stdout
"""

import sys
import re
import json

MAX_FINDINGS = 256
findings = []


def add_finding(type_, severity, line, snippet, explanation, fix, cwe):
    if len(findings) >= MAX_FINDINGS:
        return
    for f in findings:
        if f['line'] == line and f['type'] == type_:
            return
    findings.append({
        'type': type_,
        'severity': severity,
        'line': line,
        'snippet': snippet.strip(),
        'explanation': explanation,
        'fix': fix,
        'cwe': cwe,
    })


def is_string_literal(s):
    """True only if s is a pure string literal with no concatenation."""
    s = s.strip()
    if not re.match(r'^(b?r?|r?b?)["\']', s):
        return False
    # Reject concatenation: "literal" + var is still tainted
    if _has_top_level_plus(s):
        return False
    return True


def _has_top_level_plus(s):
    """Return True if s contains '+' outside of string literals."""
    in_single = in_double = False
    for c in s:
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == '+' and not in_single and not in_double:
            return True
    return False


# ------------------------------------------------------------------ #
# Detector 1: Command Injection  CWE-78                               #
# ------------------------------------------------------------------ #

def detect_command_injection(line, lineno, raw):
    m = re.search(r'\bos\.system\s*\(([^)]+)', line)
    if m:
        arg = m.group(1).strip()
        if not is_string_literal(arg):
            add_finding('Command Injection', 'HIGH', lineno, raw,
                'os.system() is called with a variable argument. If any part of the string '
                'originates from user input, an attacker can inject shell metacharacters '
                '(;, |, $(), etc.) to execute arbitrary commands on the host system.',
                'Replace os.system() with subprocess.run(["cmd", arg], shell=False) '
                'passing arguments as a list to prevent shell interpretation.',
                'CWE-78')

    if re.search(r'\bsubprocess\.(run|call|Popen|check_output|check_call)\b', line):
        if re.search(r'\bshell\s*=\s*True\b', line):
            add_finding('Command Injection', 'HIGH', lineno, raw,
                'subprocess is invoked with shell=True, which passes the command string through '
                'the shell. If any part of the command is user-controlled, shell metacharacters '
                'can be injected to run arbitrary commands.',
                'Use shell=False (the default) and supply arguments as a list: '
                'subprocess.run(["program", arg1, arg2], shell=False).',
                'CWE-78')

    m = re.search(r'\bos\.popen\s*\(([^)]+)', line)
    if m:
        arg = m.group(1).strip()
        if not is_string_literal(arg):
            add_finding('Command Injection', 'HIGH', lineno, raw,
                'os.popen() executes a shell command. With a variable argument, an attacker can '
                'inject arbitrary shell commands if the input is not fully sanitized.',
                'Replace os.popen() with subprocess.run() using a list of arguments '
                'and shell=False to eliminate shell interpretation.',
                'CWE-78')


# ------------------------------------------------------------------ #
# Detector 2: Code Injection  CWE-94                                  #
# ------------------------------------------------------------------ #

def detect_code_injection(line, lineno, raw):
    m = re.search(r'\beval\s*\((.+)', line)
    if m:
        arg = m.group(1).split(')')[0].strip()
        if not is_string_literal(arg):
            add_finding('Code Injection', 'HIGH', lineno, raw,
                "eval() executes a string as Python code at runtime. If the argument "
                "contains any user-controlled data, an attacker can execute arbitrary "
                "Python code with the process's full privileges, including file system "
                "access, network calls, and system commands.",
                'Avoid eval() entirely. For safe literal parsing, use ast.literal_eval(). '
                'Redesign the logic to use explicit function calls or a dispatch table.',
                'CWE-94')

    m = re.search(r'\bexec\s*\((.+)', line)
    if m:
        arg = m.group(1).split(')')[0].strip()
        if not is_string_literal(arg):
            add_finding('Code Injection', 'HIGH', lineno, raw,
                'exec() executes arbitrary Python code passed as a string. An attacker who '
                'controls the argument gains full code execution, identical in impact to eval().',
                'Avoid exec() with untrusted input. Refactor to explicit function dispatch '
                'instead of dynamic code execution.',
                'CWE-94')


# ------------------------------------------------------------------ #
# Detector 3: SQL Injection  CWE-89                                   #
# ------------------------------------------------------------------ #

SQL_KEYWORDS = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|EXEC|EXECUTE)\b',
    re.IGNORECASE
)

def detect_sql_injection(line, lineno, raw):
    if not SQL_KEYWORDS.search(line):
        return

    # f-string interpolation containing SQL
    if re.search(r'\bf["\']', line) and '{' in line:
        add_finding('SQL Injection', 'HIGH', lineno, raw,
            'An SQL query is built using an f-string with variable interpolation. '
            'An attacker who controls any interpolated variable can inject arbitrary SQL '
            'to read, modify, or delete data, or bypass authentication.',
            'Use parameterized queries: cursor.execute("SELECT ... WHERE id = ?", (user_id,)). '
            'Never build SQL by string interpolation, %-formatting, or concatenation.',
            'CWE-89')
        return

    # %-formatting containing SQL keyword in a string literal
    if re.search(r'%\s*[(\w]', line) and re.search(r'["\'].*' + SQL_KEYWORDS.pattern, line, re.IGNORECASE):
        add_finding('SQL Injection', 'HIGH', lineno, raw,
            'An SQL query is constructed using %-style string formatting with variables. '
            'This allows an attacker who controls any formatted value to inject SQL statements '
            'that alter the query structure.',
            'Use parameterized queries: cursor.execute("SELECT ... WHERE id = ?", (user_id,)). '
            'Keep SQL code and data strictly separated.',
            'CWE-89')
        return

    # .format() on a string containing SQL
    if re.search(r'\.format\s*\(', line) and re.search(r'["\'].*' + SQL_KEYWORDS.pattern, line, re.IGNORECASE):
        add_finding('SQL Injection', 'HIGH', lineno, raw,
            'An SQL query is constructed using .format() with variables. '
            'An attacker who controls any argument can inject arbitrary SQL.',
            'Use parameterized queries instead of .format() to build SQL statements.',
            'CWE-89')
        return

    # String concatenation with SQL keyword
    if re.search(r'["\'][^"\']*' + SQL_KEYWORDS.pattern + r'[^"\']*["\'].*\+', line, re.IGNORECASE):
        add_finding('SQL Injection', 'HIGH', lineno, raw,
            'An SQL query is built by string concatenation with a variable. '
            'An attacker who controls any concatenated value can alter the query structure.',
            'Use parameterized queries instead of string concatenation for SQL statements.',
            'CWE-89')


# ------------------------------------------------------------------ #
# Detector 4: Insecure Deserialization  CWE-502                       #
# ------------------------------------------------------------------ #

def detect_insecure_deserialization(line, lineno, raw):
    if re.search(r'\bpickle\.loads?\s*\(', line):
        add_finding('Insecure Deserialization', 'HIGH', lineno, raw,
            'pickle.load() / pickle.loads() can execute arbitrary Python code embedded in '
            'the serialized data via __reduce__. Deserializing untrusted pickle data is '
            'equivalent to remote code execution.',
            'Never deserialize pickle data from untrusted sources. '
            'Use JSON, MessagePack, or Protocol Buffers for untrusted data exchange.',
            'CWE-502')

    if re.search(r'\byaml\.load\s*\(', line):
        if not re.search(r'SafeLoader|safe_load', line):
            add_finding('Insecure Deserialization', 'HIGH', lineno, raw,
                'yaml.load() without an explicit SafeLoader can deserialize arbitrary Python '
                'objects and execute code embedded in the YAML data. This is a well-known '
                'critical vulnerability in PyYAML.',
                'Replace with yaml.safe_load(data) or '
                'yaml.load(data, Loader=yaml.SafeLoader) to restrict deserialization to safe types.',
                'CWE-502')

    if re.search(r'\bmarshal\.loads?\s*\(', line):
        add_finding('Insecure Deserialization', 'HIGH', lineno, raw,
            'marshal.loads() deserializes Python bytecode and can execute arbitrary code '
            'if the data is attacker-controlled.',
            'Avoid deserializing marshal data from untrusted sources. Use JSON for data exchange.',
            'CWE-502')


# ------------------------------------------------------------------ #
# Detector 5: Path Traversal  CWE-22                                  #
# ------------------------------------------------------------------ #

def detect_path_traversal(line, lineno, raw):
    m = re.search(r'\bopen\s*\(([^,)]+)', line)
    if m:
        arg = m.group(1).strip()
        if not is_string_literal(arg) and not arg.startswith('__'):
            if not re.fullmatch(r'[A-Z][A-Z0-9_]*', arg):
                add_finding('Path Traversal', 'MEDIUM', lineno, raw,
                    'open() is called with a variable path. If the path contains user-controlled '
                    'data without proper validation, an attacker can use "../" sequences to '
                    'traverse the directory tree and read or write arbitrary files.',
                    'Resolve the canonical path with os.path.realpath() and verify it starts '
                    'with the intended base directory before opening. '
                    'Alternatively, use pathlib.Path and check .is_relative_to(base).',
                    'CWE-22')


# ------------------------------------------------------------------ #
# Detector 6: Hardcoded Secret  CWE-798                               #
# ------------------------------------------------------------------ #

SECRET_PAT = re.compile(
    r'^\s*(password|passwd|secret|api_key|apikey|token|private_key|auth_token|'
    r'access_token|secret_key|client_secret|db_password)\s*=\s*["\']([^"\']{4,})["\']',
    re.IGNORECASE
)
PLACEHOLDER_PAT = re.compile(
    r'(your_|example|placeholder|xxx+|todo|changeme|<|\*+|test|dummy|fake|sample)',
    re.IGNORECASE
)

def detect_hardcoded_secret(line, lineno, raw):
    m = SECRET_PAT.search(line)
    if m and not PLACEHOLDER_PAT.search(m.group(2)):
        add_finding('Hardcoded Secret', 'HIGH', lineno, raw,
            'A secret value (password, API key, or token) appears hardcoded as a string literal. '
            'Hardcoded credentials are easily discovered through source code access, '
            'repository leaks, or binary inspection.',
            'Store secrets in environment variables (os.environ["SECRET"]) or a dedicated '
            'secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). '
            'Never commit credentials to version control.',
            'CWE-798')


# ------------------------------------------------------------------ #
# Detector 7: Insecure Randomness  CWE-338                            #
# ------------------------------------------------------------------ #

SECURITY_CONTEXT = re.compile(
    r'\b(token|password|passwd|secret|key|nonce|salt|session|csrf|otp|pin|auth)\b',
    re.IGNORECASE
)

def detect_insecure_randomness(line, lineno, raw):
    if re.search(r'\brandom\.(random|randint|randrange|choice|choices|sample|randbytes)\s*\(', line):
        if SECURITY_CONTEXT.search(line):
            add_finding('Insecure Randomness', 'MEDIUM', lineno, raw,
                'The random module uses a Mersenne Twister PRNG that is not cryptographically '
                'secure. Using it to generate security-sensitive values (tokens, passwords, keys, '
                'nonces) makes them predictable to an attacker who can observe enough outputs.',
                'Use the secrets module for cryptographically secure values: '
                'secrets.token_hex(32), secrets.token_urlsafe(32), or secrets.choice(alphabet).',
                'CWE-338')


# ------------------------------------------------------------------ #
# Main                                                                 #
# ------------------------------------------------------------------ #

def analyze(lines):
    for i, raw in enumerate(lines):
        lineno = i + 1
        detect_command_injection(raw, lineno, raw)
        detect_code_injection(raw, lineno, raw)
        detect_sql_injection(raw, lineno, raw)
        detect_insecure_deserialization(raw, lineno, raw)
        detect_path_traversal(raw, lineno, raw)
        detect_hardcoded_secret(raw, lineno, raw)
        detect_insecure_randomness(raw, lineno, raw)


def main():
    if len(sys.argv) >= 2:
        filepath = sys.argv[1]
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
                source = fh.read()
        except Exception as e:
            print(json.dumps({'error': str(e), 'findings': []}))
            sys.exit(1)
    else:
        source = sys.stdin.read()

    lines = source.splitlines()
    analyze(lines)
    print(json.dumps({'findings': findings}))


if __name__ == '__main__':
    main()
