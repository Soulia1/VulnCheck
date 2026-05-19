'use strict';
/**
 * VulnCheck Python Static Analysis Engine (Node.js port)
 * Detects: Buffer Overflow, Format String, Command Injection,
 *          Use-After-Free, Double Free, TOCTTOU
 * Same detectors as vulncheck_python.py — no Python runtime required.
 */

const MAX_FINDINGS = 256;

function analyzePython(source) {
  const findings = [];
  const freedVars   = new Map(); // varname -> freed_line
  const pathChecked = new Map(); // pathvar -> { line, fn }

  function addFinding(type, severity, line, snippet, explanation, fix, cwe) {
    if (findings.length >= MAX_FINDINGS) return;
    for (const f of findings) {
      if (f.line === line && f.type === type) return;
    }
    findings.push({ type, severity, line, snippet: snippet.trim(),
                    explanation, fix, cwe });
  }

  function isStringLiteral(s) {
    s = s.trim();
    if (/^f["']/.test(s)) return false;           // f-string → unsafe
    if (!/^(b?r?|r?b?)["']/.test(s)) return false; // must start with quote
    return !hasTopLevelPlus(s);                    // no concatenation
  }

  function hasTopLevelPlus(s) {
    let inS = false, inD = false;
    for (const c of s) {
      if (c === "'" && !inD) inS = !inS;
      else if (c === '"' && !inS) inD = !inD;
      else if (c === '+' && !inS && !inD) return true;
    }
    return false;
  }

  // ── Detector 1: Buffer Overflow  CWE-120 ──────────────────────────────
  function detectBufferOverflow(line, lineno, raw) {
    const m = line.match(/\bctypes\.create_string_buffer\s*\(([^)]+)/);
    if (m) {
      const arg = m[1].trim();
      if (!/^\d+$/.test(arg)) {
        addFinding('Buffer Overflow', 'HIGH', lineno, raw,
          'ctypes.create_string_buffer() is called with a variable size. ' +
          'If the size is derived from user input without validation, writing to ' +
          'this buffer via ctypes can overwrite adjacent memory — Python does not ' +
          'insert bounds checks for raw ctypes memory operations.',
          'Validate and cap the size: size = min(int(user_size), MAX_BUF). ' +
          'Prefer pure Python bytes/bytearray over ctypes buffers when possible.',
          'CWE-120');
      }
    }
    if (/\bstruct\.pack_into\s*\(/.test(line)) {
      addFinding('Buffer Overflow', 'HIGH', lineno, raw,
        'struct.pack_into() writes binary data directly into a buffer at an offset. ' +
        'If the offset or data length is user-controlled, writing past the end of ' +
        'the buffer can corrupt adjacent memory in ctypes-backed memory regions.',
        'Verify that offset + struct.calcsize(fmt) does not exceed ' +
        'len(buffer) before calling pack_into().',
        'CWE-120');
    }
    const m2 = line.match(/\bctypes\.\w+\.from_buffer_copy\s*\(([^)]+)/);
    if (m2 && !isStringLiteral(m2[1].trim())) {
      addFinding('Buffer Overflow', 'HIGH', lineno, raw,
        'ctypes from_buffer_copy() copies raw bytes into a typed buffer. ' +
        'If the source data is larger than the destination type, it can ' +
        'silently overflow into adjacent memory with mismatched sizes.',
        'Ensure len(source_data) === ctypes.sizeof(DestType) before calling from_buffer_copy().',
        'CWE-120');
    }
  }

  // ── Detector 2: Format String  CWE-134 ────────────────────────────────
  function detectFormatString(line, lineno, raw) {
    // logging.*(var) with a single arg that is not a literal
    const logM = line.match(
      /\b(?:logging|log|logger)\.(debug|info|warning|warn|error|critical)\s*\(([^)]+)/
    );
    if (logM) {
      const arg = logM[2].trim();
      if (!isStringLiteral(arg) && !arg.includes(',') && !/^f["']/.test(arg)) {
        addFinding('Format String', 'HIGH', lineno, raw,
          'A logging call passes a non-literal string directly as the format ' +
          'argument with no additional arguments. If that string is user-controlled ' +
          'and contains %-specifiers, the logging framework will attempt string ' +
          'formatting, potentially raising exceptions or leaking internal data.',
          'Pass a literal format string: logging.info("%s", user_msg) ' +
          'or logging.info(`${user_msg}`) to prevent format string interpretation.',
          'CWE-134');
      }
    }
    // var % (tuple) or var % {dict} — skip comments and numeric modulo
    const stripped = raw.trim();
    if (!stripped.startsWith('#')) {
      const fmtM = line.match(/(?<!["\'\w])([a-zA-Z_]\w*)\s*%\s*[({'"]/);
      if (fmtM) {
        const fmtVar = fmtM[1];
        const RESERVED = new Set(['if','else','elif','while','for','in','not',
          'and','or','True','False','None','return','import','from','class',
          'def','print','len','range','int','str','bytes','list','dict',
          'set','tuple','type','super','object']);
        if (!RESERVED.has(fmtVar)) {
          addFinding('Format String', 'HIGH', lineno, raw,
            'The left operand of the % format operator is a variable, not a ' +
            'string literal. If this variable contains user-supplied data, an ' +
            'attacker can inject format specifiers (%s, %d, %x) to extract data ' +
            'or cause unexpected behaviour.',
            'Always use a literal format string: print("%s", user_input) ' +
            'rather than passing a user-controlled variable as the format.',
            'CWE-134');
        }
      }
    }
  }

  // ── Detector 3: Command Injection  CWE-78 ─────────────────────────────
  function detectCommandInjection(line, lineno, raw) {
    const m1 = line.match(/\bos\.system\s*\(([^)]+)/);
    if (m1 && !isStringLiteral(m1[1].trim())) {
      addFinding('Command Injection', 'HIGH', lineno, raw,
        'os.system() is called with a variable argument. If any part of the string ' +
        'originates from user input, an attacker can inject shell metacharacters ' +
        '(;, |, $(), etc.) to execute arbitrary commands on the host system.',
        'Replace os.system() with subprocess.run(["cmd", arg], shell=False) ' +
        'passing arguments as a list to prevent shell interpretation.',
        'CWE-78');
    }
    if (/\bsubprocess\.(run|call|Popen|check_output|check_call)\b/.test(line) &&
        /\bshell\s*=\s*True\b/.test(line)) {
      addFinding('Command Injection', 'HIGH', lineno, raw,
        'subprocess is invoked with shell=True, which passes the command string ' +
        'through the shell. If any part of the command is user-controlled, shell ' +
        'metacharacters can be injected to run arbitrary commands.',
        'Use shell=False (the default) and supply arguments as a list: ' +
        'subprocess.run(["program", arg1, arg2], shell=False).',
        'CWE-78');
    }
    const m2 = line.match(/\bos\.popen\s*\(([^)]+)/);
    if (m2 && !isStringLiteral(m2[1].trim())) {
      addFinding('Command Injection', 'HIGH', lineno, raw,
        'os.popen() executes a shell command. With a variable argument, an attacker ' +
        'can inject arbitrary shell commands if the input is not fully sanitized.',
        'Replace os.popen() with subprocess.run() using a list of arguments ' +
        'and shell=False to eliminate shell interpretation.',
        'CWE-78');
    }
  }

  // ── Detector 4 & 5: Use-After-Free / Double Free  CWE-416, CWE-415 ────
  function detectUafAndDoubleFree(line, lineno, raw) {
    const freeM = line.match(/\b(?:libc|msvcrt|cdll(?:\.\w+)?)\.free\s*\((\w+)/);
    if (freeM) {
      const varname = freeM[1];
      if (freedVars.has(varname)) {
        const prev = freedVars.get(varname);
        addFinding('Double Free', 'HIGH', lineno, raw,
          `The ctypes pointer '${varname}' was already freed at line ${prev}. ` +
          "Freeing it a second time corrupts the allocator's internal metadata and " +
          'can be exploited via heap-manipulation techniques to achieve arbitrary code execution.',
          `Set ${varname} = None immediately after the first free(). ` +
          'Subsequent operations on None raise AttributeError, making the double-free visible.',
          'CWE-415');
      } else {
        freedVars.set(varname, lineno);
      }
      return; // don't also check UAF on the free() line itself
    }

    // Check if any freed variable is used on this line
    for (const [varname, freedLine] of freedVars) {
      if (new RegExp(`\\b${varname}\\b`).test(line)) {
        addFinding('Use-After-Free', 'HIGH', lineno, raw,
          `The ctypes pointer '${varname}' was freed at line ${freedLine} but is ` +
          'accessed here. The underlying memory may have been reallocated and ' +
          'overwritten, causing data corruption or an exploitable use-after-free.',
          `Set '${varname} = None' immediately after free(). ` +
          'Add a None-check before any subsequent dereference.',
          'CWE-416');
      }
    }

    // Reset freed flag if variable is reassigned
    for (const varname of [...freedVars.keys()]) {
      if (new RegExp(`\\b${varname}\\s*=(?!=)`).test(line)) {
        freedVars.delete(varname);
      }
    }
  }

  // ── Detector 6: TOCTTOU  CWE-367 ──────────────────────────────────────
  const CHECK_FNS = [
    ['os.access',      /os\.access\s*\(([^,)]+)/],
    ['os.path.exists', /os\.path\.exists\s*\(([^,)]+)/],
    ['os.path.isfile', /os\.path\.isfile\s*\(([^,)]+)/],
    ['os.stat',        /os\.stat\s*\(([^,)]+)/],
    ['os.lstat',       /os\.lstat\s*\(([^,)]+)/],
  ];
  const USE_FNS = [
    ['open',        /\bopen\s*\(([^,)]+)/],
    ['os.open',     /os\.open\s*\(([^,)]+)/],
    ['os.remove',   /os\.remove\s*\(([^,)]+)/],
    ['os.unlink',   /os\.unlink\s*\(([^,)]+)/],
    ['os.rename',   /os\.rename\s*\(([^,)]+)/],
    ['os.chmod',    /os\.chmod\s*\(([^,)]+)/],
    ['shutil.copy', /shutil\.copy\s*\(([^,)]+)/],
    ['shutil.move', /shutil\.move\s*\(([^,)]+)/],
  ];

  function detectTocttou(line, lineno, raw) {
    for (const [fnName, pat] of CHECK_FNS) {
      const m = line.match(pat);
      if (m) {
        const pathvar = m[1].trim().replace(/^['"]|['"]$/g, '');
        pathChecked.set(pathvar, { line: lineno, fn: fnName });
      }
    }
    for (const [fnName, pat] of USE_FNS) {
      const m = line.match(pat);
      if (m) {
        const pathvar = m[1].trim().replace(/^['"]|['"]$/g, '');
        if (pathChecked.has(pathvar)) {
          const { line: checkLine, fn: checkFn } = pathChecked.get(pathvar);
          if (checkLine !== lineno) {
            addFinding('TOCTTOU', 'MEDIUM', lineno, raw,
              `The path '${pathvar}' was checked at line ${checkLine} with ` +
              `${checkFn}() but used here with ${fnName}(). Between the check ` +
              'and the use a race condition exists: an attacker can replace the ' +
              'file (e.g. with a symlink) after the check passes.',
              'Eliminate the TOCTOU window: open the file directly and handle ' +
              'the exception if it is missing or inaccessible. ' +
              'Never rely on os.access() or os.path.exists() for security decisions.',
              'CWE-367');
            pathChecked.delete(pathvar);
          }
        }
      }
    }
  }

  // ── Main analysis loop ─────────────────────────────────────────────────
  const lines = source.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw    = lines[i];
    const lineno = i + 1;
    detectBufferOverflow(raw, lineno, raw);
    detectFormatString(raw, lineno, raw);
    detectCommandInjection(raw, lineno, raw);
    detectUafAndDoubleFree(raw, lineno, raw);
    detectTocttou(raw, lineno, raw);
  }

  return { findings };
}

module.exports = { analyzePython };
