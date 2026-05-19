#!/usr/bin/env python3
"""
VulnCheck Python Static Analysis Engine
Detects Python equivalents of:
  Buffer Overflow, Format String, Command Injection,
  Use-After-Free, Double Free, TOCTTOU
Output: JSON to stdout
"""

import sys
import re
import json

MAX_FINDINGS = 256
findings = []

freed_vars   = {}   # varname -> freed_line  (Use-After-Free / Double Free)
path_checked = {}   # pathvar -> (check_line, check_fn)  (TOCTTOU)


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
    """True only for pure, non-concatenated string literals (not f-strings)."""
    s = s.strip()
    if re.match(r'^f["\']', s):
        return False
    if not re.match(r'^(b?r?|r?b?)["\']', s):
        return False
    return not _has_top_level_plus(s)


def _has_top_level_plus(s):
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
# Detector 1: Buffer Overflow  CWE-120                                #
# ------------------------------------------------------------------ #

def detect_buffer_overflow(line, lineno, raw):
    # ctypes.create_string_buffer(variable_size)
    m = re.search(r'\bctypes\.create_string_buffer\s*\(([^)]+)', line)
    if m:
        arg = m.group(1).strip()
        if not re.match(r'^\d+$', arg):
            add_finding('Buffer Overflow', 'HIGH', lineno, raw,
                'ctypes.create_string_buffer() is called with a variable size. '
                'If the size is derived from user input without validation, writing to '
                'this buffer via ctypes can overwrite adjacent memory — Python does not '
                'insert bounds checks for raw ctypes memory operations.',
                'Validate and cap the size before allocation: '
                'size = min(int(user_size), MAX_BUF). '
                'Prefer pure Python bytes/bytearray over ctypes buffers when possible.',
                'CWE-120')

    # struct.pack_into — writes into a fixed buffer at an offset
    if re.search(r'\bstruct\.pack_into\s*\(', line):
        add_finding('Buffer Overflow', 'HIGH', lineno, raw,
            'struct.pack_into() writes binary data directly into a buffer at an offset. '
            'If the offset or data length is user-controlled, writing past the end of the '
            'buffer can corrupt adjacent memory in ctypes-backed memory regions.',
            'Verify that offset + struct.calcsize(fmt) does not exceed '
            'len(buffer) before calling pack_into().',
            'CWE-120')

    # bytearray / bytes copy into ctypes buffer without size check
    m = re.search(r'\bctypes\.\w+\.from_buffer_copy\s*\(([^)]+)', line)
    if m:
        arg = m.group(1).strip()
        if not is_string_literal(arg):
            add_finding('Buffer Overflow', 'HIGH', lineno, raw,
                'ctypes from_buffer_copy() copies raw bytes into a typed buffer. '
                'If the source data is larger than the destination type, '
                'it raises ValueError — but with mismapped sizes it can silently '
                'overflow into adjacent memory.',
                'Ensure len(source_data) == ctypes.sizeof(DestType) before calling '
                'from_buffer_copy().',
                'CWE-120')


# ------------------------------------------------------------------ #
# Detector 2: Format String  CWE-134                                  #
# ------------------------------------------------------------------ #

def detect_format_string(line, lineno, raw):
    # logging.*(var) with no comma — var used directly as the format string
    log_m = re.search(
        r'\b(?:logging|log|logger)\.(debug|info|warning|warn|error|critical)\s*\(([^)]+)',
        line
    )
    if log_m:
        arg = log_m.group(2).strip()
        if not is_string_literal(arg) and ',' not in arg:
            if not re.match(r'^f["\']', arg):
                add_finding('Format String', 'HIGH', lineno, raw,
                    'A logging call passes a non-literal string directly as the format '
                    'argument with no additional arguments. If that string is user-controlled '
                    'and contains %-specifiers, the logging framework will attempt string '
                    'formatting, potentially raising exceptions or leaking internal data.',
                    'Pass a literal format string: logging.info("%s", user_msg) '
                    'or logging.info(f"{user_msg}") to prevent format string interpretation.',
                    'CWE-134')

    # var % (args) — left operand is a variable, right is a tuple/dict (not math)
    # Only flag when right side is clearly format-string args: ( or { or "
    # This avoids false positives from modulo math: x % 2, count % 100
    stripped = raw.strip()
    if not stripped.startswith('#'):
        m = re.search(r'(?<!["\'\w])(\b[a-zA-Z_]\w*)\s*%\s*[({"\']', line)
        if m:
            fmt_var = m.group(1)
            reserved = {'if', 'else', 'elif', 'while', 'for', 'in', 'not',
                        'and', 'or', 'True', 'False', 'None', 'return',
                        'import', 'from', 'class', 'def', 'print', 'len',
                        'range', 'int', 'str', 'bytes', 'list', 'dict',
                        'set', 'tuple', 'type', 'super', 'object'}
            if fmt_var not in reserved:
                add_finding('Format String', 'HIGH', lineno, raw,
                    'The left operand of the %% format operator is a variable, not a '
                    'string literal. If this variable contains user-supplied data, an '
                    'attacker can inject format specifiers (%s, %d, %x) to extract data '
                    'or cause unexpected behaviour in logging and output functions.',
                    'Always use a literal format string: '
                    'print("%s", user_input) or f"{user_input}" '
                    'rather than passing a user-controlled variable as the format.',
                    'CWE-134')


# ------------------------------------------------------------------ #
# Detector 3: Command Injection  CWE-78                               #
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
                'subprocess is invoked with shell=True, which passes the command string '
                'through the shell. If any part of the command is user-controlled, shell '
                'metacharacters can be injected to run arbitrary commands.',
                'Use shell=False (the default) and supply arguments as a list: '
                'subprocess.run(["program", arg1, arg2], shell=False).',
                'CWE-78')

    m = re.search(r'\bos\.popen\s*\(([^)]+)', line)
    if m:
        arg = m.group(1).strip()
        if not is_string_literal(arg):
            add_finding('Command Injection', 'HIGH', lineno, raw,
                'os.popen() executes a shell command. With a variable argument, an attacker '
                'can inject arbitrary shell commands if the input is not fully sanitized.',
                'Replace os.popen() with subprocess.run() using a list of arguments '
                'and shell=False to eliminate shell interpretation.',
                'CWE-78')


# ------------------------------------------------------------------ #
# Detector 4 & 5: Use-After-Free / Double Free  CWE-416, CWE-415      #
# Multi-line via ctypes free() tracking                                #
# ------------------------------------------------------------------ #

def detect_uaf_and_double_free(line, lineno, raw):
    # Detect ctypes free calls: libc.free(ptr), cdll.msvcrt.free(ptr), etc.
    free_m = re.search(
        r'\b(?:libc|msvcrt|cdll(?:\.\w+)?)\.free\s*\((\w+)',
        line
    )
    if free_m:
        varname = free_m.group(1)
        if varname in freed_vars:
            prev_line = freed_vars[varname]
            add_finding('Double Free', 'HIGH', lineno, raw,
                f"The ctypes pointer '{varname}' was already freed at line {prev_line}. "
                "Freeing it a second time corrupts the allocator's internal metadata and "
                "can be exploited via heap-manipulation techniques to achieve arbitrary "
                "code execution.",
                f"Set {varname} = None immediately after the first free(). "
                "Subsequent operations on None will raise AttributeError, making the "
                "double-free visible rather than silently corrupting memory.",
                'CWE-415')
        else:
            freed_vars[varname] = lineno
        return  # don't also check UAF on the free() line itself

    # Check if any freed variable is used on this line
    for varname, freed_line in list(freed_vars.items()):
        if re.search(r'\b' + re.escape(varname) + r'\b', line):
            add_finding('Use-After-Free', 'HIGH', lineno, raw,
                f"The ctypes pointer '{varname}' was freed at line {freed_line} but is "
                "accessed here. The underlying memory may have been reallocated and "
                "overwritten, causing data corruption or an exploitable use-after-free.",
                f"Set '{varname} = None' immediately after free(). "
                "Add a None-check before any subsequent dereference, or restructure "
                "ownership so the pointer is inaccessible after its lifetime ends.",
                'CWE-416')

    # Reset freed flag if variable is reassigned
    for varname in list(freed_vars.keys()):
        if re.search(r'\b' + re.escape(varname) + r'\s*=(?!=)', line):
            del freed_vars[varname]


# ------------------------------------------------------------------ #
# Detector 6: TOCTTOU  CWE-367                                        #
# ------------------------------------------------------------------ #

CHECK_FNS = [
    ('os.access',       r'os\.access\s*\(([^,)]+)'),
    ('os.path.exists',  r'os\.path\.exists\s*\(([^,)]+)'),
    ('os.path.isfile',  r'os\.path\.isfile\s*\(([^,)]+)'),
    ('os.stat',         r'os\.stat\s*\(([^,)]+)'),
    ('os.lstat',        r'os\.lstat\s*\(([^,)]+)'),
]

USE_FNS = [
    ('open',         r'\bopen\s*\(([^,)]+)'),
    ('os.open',      r'os\.open\s*\(([^,)]+)'),
    ('os.remove',    r'os\.remove\s*\(([^,)]+)'),
    ('os.unlink',    r'os\.unlink\s*\(([^,)]+)'),
    ('os.rename',    r'os\.rename\s*\(([^,)]+)'),
    ('os.chmod',     r'os\.chmod\s*\(([^,)]+)'),
    ('shutil.copy',  r'shutil\.copy\s*\(([^,)]+)'),
    ('shutil.move',  r'shutil\.move\s*\(([^,)]+)'),
]

def detect_tocttou(line, lineno, raw):
    # Step 1: record path variable when a check function is called
    for fn_name, pattern in CHECK_FNS:
        m = re.search(pattern, line)
        if m:
            pathvar = m.group(1).strip().strip('"\'')
            path_checked[pathvar] = (lineno, fn_name)

    # Step 2: detect use of a previously checked path
    for fn_name, pattern in USE_FNS:
        m = re.search(pattern, line)
        if m:
            pathvar = m.group(1).strip().strip('"\'')
            if pathvar in path_checked:
                check_line, check_fn = path_checked[pathvar]
                if check_line != lineno:
                    add_finding('TOCTTOU', 'MEDIUM', lineno, raw,
                        f"The path '{pathvar}' was checked at line {check_line} with "
                        f"{check_fn}() but used here with {fn_name}(). Between the check "
                        "and the use a race condition exists: an attacker can replace the "
                        "file (e.g. with a symlink) after the check passes, forcing the "
                        "program to operate on an unintended target.",
                        "Eliminate the TOCTOU window: open the file directly and handle "
                        "the exception if it is missing or inaccessible. "
                        "Never rely on os.access() or os.path.exists() for security decisions.",
                        'CWE-367')
                    del path_checked[pathvar]


# ------------------------------------------------------------------ #
# Main                                                                 #
# ------------------------------------------------------------------ #

def analyze(lines):
    for i, raw in enumerate(lines):
        lineno = i + 1
        detect_buffer_overflow(raw, lineno, raw)
        detect_format_string(raw, lineno, raw)
        detect_command_injection(raw, lineno, raw)
        detect_uaf_and_double_free(raw, lineno, raw)
        detect_tocttou(raw, lineno, raw)


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
