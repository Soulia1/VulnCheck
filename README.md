# VulnCheck — Educational C Vulnerability Checker

A lightweight static analysis tool for students learning secure software development.
Detects 6 common vulnerability classes in C source code with line-level findings,
CWE identifiers, educational explanations, and fix suggestions.

---

## Detected Vulnerabilities

| Class | CWE | Severity |
|---|---|---|
| Buffer Overflow | CWE-120 | HIGH |
| Format String | CWE-134 | HIGH |
| Command Injection | CWE-78 | HIGH |
| Use-After-Free | CWE-416 | HIGH |
| Double Free | CWE-415 | HIGH |
| TOCTTOU / Race Condition | CWE-367 | MEDIUM |

---

## Quick Start

### 1. Build the C engine

```bash
make
```

Requires `gcc`. Produces the `./vulncheck` binary.

### 2. Install Node.js dependencies

```bash
npm install
```

### 3. Start the server

```bash
npm start
# or
node server.js
```

Opens at **http://localhost:3000**

---

## Usage

### Option A — Paste code in the browser
1. Open http://localhost:3000
2. Paste or type C code into the editor
3. Click **Analyze Code** (or press Ctrl+Enter / ⌘+Enter)

### Option B — Upload a .c file
1. Click the **upload .c** button in the editor title bar
2. Select any `.c` source file from your machine
3. The file loads into the editor and analysis runs automatically

### Option C — Command line (engine only)
```bash
# Analyze a file directly
./vulncheck mycode.c

# Pipe from stdin
cat mycode.c | ./vulncheck --stdin

# Pretty-print JSON output
./vulncheck mycode.c | python3 -m json.tool
```

### Option D — REST API
```bash
# POST code text
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"code": "#include <stdio.h>\nvoid f(char*s){char b[8];strcpy(b,s);}", "language": "c"}'

# POST a file
curl -X POST http://localhost:3000/analyze/upload \
  -F "file=@yourfile.c"
```

---

## Project Structure

```
vulncheck/
├── vulncheck.c       C static analysis engine (all detection logic)
├── vulncheck         Compiled binary (created by make)
├── Makefile          Build config
├── server.js         Node.js/Express API + static file server
├── package.json      Node dependencies (express, multer)
├── VulnCheck.html    Frontend entry point
├── app.jsx           React UI (compiled by Babel in-browser)
└── assets/
    ├── shadow-mask.png
    └── shadow-noise.png
```

---

## JSON Output Schema

```json
{
  "findings": [
    {
      "type": "Buffer Overflow",
      "severity": "HIGH",
      "line": 8,
      "snippet": "strcpy(buf, name);",
      "explanation": "strcpy() copies bytes with no length check ...",
      "fix": "Use strncpy(dst, src, sizeof(dst)-1) ...",
      "cwe": "CWE-120"
    }
  ]
}
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Engine status check |
| POST | `/analyze` | Analyze code from JSON body `{ code, language }` |
| POST | `/analyze/upload` | Analyze uploaded `.c` file (multipart/form-data field: `file`) |

---

## Limitations (by design)

- **C only** — this tool is scoped to C for educational focus
- **Heuristic-based** — line-by-line pattern matching, not a full AST/IR analysis
- **No interprocedural analysis** — does not trace calls across function boundaries
- **No pointer aliasing** — two pointers to the same memory are treated independently
- Pair results with manual review, fuzzing, and sanitizers (AddressSanitizer, Valgrind) for real-world use

---

## Requirements

- GCC (any modern version)
- Node.js 18+
- npm
