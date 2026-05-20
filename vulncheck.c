/*
 * VulnCheck - Educational C Static Analysis Engine
 * Detects: Buffer Overflow, Format String, Command Injection,
 *          Use-After-Free, Double Free, TOCTTOU
 * Output: JSON to stdout
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Config                                                               */
/* ------------------------------------------------------------------ */

#define MAX_LINES       8192
#define MAX_LINE_LEN    2048
#define MAX_FINDINGS    256
#define MAX_VARS        256
#define MAX_VAR_LEN     128
#define MAX_SNIPPET_LEN 512
#define MAX_EXPL_LEN    1024
#define MAX_FIX_LEN     1024

/* ------------------------------------------------------------------ */
/* Data structures                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    char type[64];
    char severity[16];
    int  line;
    char snippet[MAX_SNIPPET_LEN];
    char explanation[MAX_EXPL_LEN];
    char fix[MAX_FIX_LEN];
    char cwe[32];
} Finding;

typedef struct {
    char name[MAX_VAR_LEN];
    int  freed_line;          /* line where free() was called */
    int  is_freed;
    int  is_path_checked;     /* set when access()/stat() seen */
    int  check_line;
} VarState;

static Finding   findings[MAX_FINDINGS];
static int       finding_count = 0;

static VarState  vars[MAX_VARS];
static int       var_count = 0;

typedef struct {
    char name[MAX_VAR_LEN];
    int  taint_line;
    int  is_tainted;
} TaintVar;

static TaintVar  tainted_vars[MAX_VARS];
static int       tainted_count = 0;

/* ------------------------------------------------------------------ */
/* Utility helpers                                                      */
/* ------------------------------------------------------------------ */

/* Trim leading whitespace, return pointer into s */
static const char *ltrim(const char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

/* Check if character is a valid identifier character */
static int is_ident(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

/* Extract the first argument inside function call parens.
   src points just after the '(' of func(
   result written to buf, max len buflen */
static void extract_first_arg(const char *src, char *buf, int buflen) {
    const char *p = src;
    int depth = 0, i = 0;
    /* skip whitespace */
    while (*p && isspace((unsigned char)*p)) p++;
    while (*p && i < buflen - 1) {
        if (*p == '(') depth++;
        else if (*p == ')') {
            if (depth == 0) break;
            depth--;
        } else if (*p == ',' && depth == 0) break;
        buf[i++] = *p++;
    }
    buf[i] = '\0';
    /* trim trailing whitespace */
    while (i > 0 && isspace((unsigned char)buf[i-1])) buf[--i] = '\0';
}

/* Extract variable name from a free() call: free(ptr) -> "ptr"
   Also handles free(ptr->x), free(*ptr) -> strip decorators */
static void extract_free_arg(const char *src, char *buf, int buflen) {
    char raw[MAX_VAR_LEN] = {0};
    extract_first_arg(src, raw, sizeof(raw));
    /* strip leading *, &, spaces */
    const char *p = raw;
    while (*p == '*' || *p == '&' || *p == ' ') p++;
    /* copy until non-ident, non-dot, non-arrow */
    int i = 0;
    while (*p && (is_ident(*p)) && i < buflen - 1) {
        buf[i++] = *p++;
    }
    buf[i] = '\0';
}

/* Return pointer to first argument position after func name in line.
   e.g. for "  printf(x, y)" with fname="printf", returns pointer to "x, y)" */
static const char *find_call_args(const char *line, const char *fname) {
    const char *p = line;
    size_t flen = strlen(fname);
    while (*p) {
        /* match function name not preceded by identifier char */
        if ((p == line || !is_ident((unsigned char)*(p-1))) &&
            strncmp(p, fname, flen) == 0 &&
            !is_ident((unsigned char)p[flen])) {
            const char *q = p + flen;
            while (*q && isspace((unsigned char)*q)) q++;
            if (*q == '(') return q + 1;
        }
        p++;
    }
    return NULL;
}

/* Check if a variable name appears in a line (as a token) */
static int var_used_in_line(const char *line, const char *varname) {
    if (!varname || varname[0] == '\0') return 0;
    const char *p = line;
    size_t vlen = strlen(varname);
    while (*p) {
        if ((p == line || !is_ident((unsigned char)*(p-1))) &&
            strncmp(p, varname, vlen) == 0 &&
            !is_ident((unsigned char)p[vlen])) {
            return 1;
        }
        p++;
    }
    return 0;
}

/* Safely escape a string for JSON output */
static void json_escape(const char *src, char *dst, int dstlen) {
    int i = 0;
    while (*src && i < dstlen - 3) {
        unsigned char c = (unsigned char)*src++;
        if (c == '"')       { dst[i++] = '\\'; dst[i++] = '"'; }
        else if (c == '\\') { dst[i++] = '\\'; dst[i++] = '\\'; }
        else if (c == '\n') { dst[i++] = '\\'; dst[i++] = 'n'; }
        else if (c == '\r') { dst[i++] = '\\'; dst[i++] = 'r'; }
        else if (c == '\t') { dst[i++] = '\\'; dst[i++] = 't'; }
        else if (c < 0x20)  { /* skip other control chars */ }
        else                { dst[i++] = c; }
    }
    dst[i] = '\0';
}

/* Add a finding to the list (avoid exact duplicates on same line+type) */
static void add_finding(const char *type, const char *severity, int line,
                        const char *snippet, const char *explanation,
                        const char *fix, const char *cwe) {
    if (finding_count >= MAX_FINDINGS) return;
    /* dedup: same type + line */
    for (int i = 0; i < finding_count; i++) {
        if (findings[i].line == line && strcmp(findings[i].type, type) == 0)
            return;
    }
    Finding *f = &findings[finding_count++];
    strncpy(f->type,        type,        sizeof(f->type)-1);
    strncpy(f->severity,    severity,    sizeof(f->severity)-1);
    f->line = line;
    /* trim snippet */
    const char *s = ltrim(snippet);
    strncpy(f->snippet,     s,           sizeof(f->snippet)-1);
    strncpy(f->explanation, explanation, sizeof(f->explanation)-1);
    strncpy(f->fix,         fix,         sizeof(f->fix)-1);
    strncpy(f->cwe,         cwe,         sizeof(f->cwe)-1);
}

/* ------------------------------------------------------------------ */
/* Taint + format-string helpers                                        */
/* ------------------------------------------------------------------ */

static TaintVar *get_tainted_var(const char *name) {
    for (int i = 0; i < tainted_count; i++) {
        if (strcmp(tainted_vars[i].name, name) == 0)
            return &tainted_vars[i];
    }
    if (tainted_count >= MAX_VARS) return NULL;
    TaintVar *tv = &tainted_vars[tainted_count++];
    memset(tv, 0, sizeof(*tv));
    strncpy(tv->name, name, MAX_VAR_LEN - 1);
    return tv;
}

/* Extract the Nth argument (1-based) from a call-args string */
static void extract_nth_arg(const char *src, int n, char *buf, int buflen) {
    const char *p = src;
    for (int a = 1; a < n; a++) {
        int depth = 0;
        while (*p) {
            if      (*p == '(')                       depth++;
            else if (*p == ')') { if (!depth) { buf[0] = '\0'; return; } depth--; }
            else if (*p == ',' && !depth)             { p++; break; }
            p++;
        }
        if (!*p) { buf[0] = '\0'; return; }
    }
    extract_first_arg(p, buf, buflen);
}

/* Count comma-separated arguments starting from position p (depth + string aware).
   Stops at an unmatched ')'. */
static int count_args_from(const char *p) {
    int count = 0, depth = 0, in_str = 0;
    while (*p) {
        if (in_str) {
            if (*p == '\\')     { if (*(p+1)) p++; }
            else if (*p == '"') { in_str = 0; }
        } else {
            if      (*p == '"')                      in_str = 1;
            else if (*p == '(')                      depth++;
            else if (*p == ')') { if (!depth) break; depth--; }
            else if (*p == ',' && !depth)            count++;
        }
        p++;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Var state helpers                                                    */
/* ------------------------------------------------------------------ */

static VarState *get_var(const char *name) {
    for (int i = 0; i < var_count; i++) {
        if (strcmp(vars[i].name, name) == 0) return &vars[i];
    }
    if (var_count >= MAX_VARS) return NULL;
    VarState *v = &vars[var_count++];
    memset(v, 0, sizeof(*v));
    strncpy(v->name, name, MAX_VAR_LEN - 1);
    return v;
}

/* ------------------------------------------------------------------ */
/* Detector 1: Buffer Overflow                                          */
/* CWE-120, CWE-121, CWE-122                                           */
/* ------------------------------------------------------------------ */

static void detect_buffer_overflow(const char *line, int lineno,
                                   const char *raw) {
    /* strcpy(dst, src) - unbounded */
    if (find_call_args(line, "strcpy")) {
        add_finding(
            "Buffer Overflow", "HIGH", lineno, raw,
            "strcpy() copies bytes until a null terminator with no length check. "
            "If the source string is longer than the destination buffer, "
            "adjacent memory is overwritten, enabling stack smashing or heap corruption.",
            "Use strncpy(dst, src, sizeof(dst)-1) and null-terminate manually, "
            "or prefer strlcpy() / snprintf() which enforce a size limit.",
            "CWE-120"
        );
    }

    /* strcat(dst, src) - unbounded */
    if (find_call_args(line, "strcat")) {
        add_finding(
            "Buffer Overflow", "HIGH", lineno, raw,
            "strcat() appends without checking the remaining capacity of the "
            "destination buffer, potentially writing past its end.",
            "Use strncat(dst, src, sizeof(dst) - strlen(dst) - 1) "
            "or snprintf() to keep all concatenation within bounds.",
            "CWE-120"
        );
    }

    /* gets() - always unsafe */
    if (find_call_args(line, "gets")) {
        add_finding(
            "Buffer Overflow", "HIGH", lineno, raw,
            "gets() reads an unlimited number of bytes from stdin into the buffer "
            "with no size limit whatsoever. It was removed from the C11 standard "
            "precisely because it cannot be used safely.",
            "Replace with fgets(buf, sizeof(buf), stdin) which respects the buffer size.",
            "CWE-120"
        );
    }

    /* sprintf(buf, ...) without snprintf */
    if (find_call_args(line, "sprintf") && !find_call_args(line, "snprintf")) {
        add_finding(
            "Buffer Overflow", "HIGH", lineno, raw,
            "sprintf() formats into a fixed buffer with no length limit. "
            "A sufficiently long format result will overflow the destination "
            "buffer and corrupt adjacent memory.",
            "Replace with snprintf(buf, sizeof(buf), fmt, ...) to limit output length.",
            "CWE-120"
        );
    }

    /* scanf(\"%s\") without width specifier */
    {
        const char *p = find_call_args(line, "scanf");
        if (!p) p = find_call_args(line, "fscanf");
        if (p) {
            /* look for %s inside the format literal without a width number */
            const char *q = p;
            while (*q) {
                if (*q == '%' && *(q+1) == 's') {
                    add_finding(
                        "Buffer Overflow", "HIGH", lineno, raw,
                        "scanf(\"%s\", buf) reads a whitespace-delimited token of "
                        "unlimited length into buf. An attacker controlling input "
                        "can overflow the buffer.",
                        "Add an explicit width: scanf(\"%31s\", buf) for a 32-byte buffer, "
                        "or use fgets() instead.",
                        "CWE-120"
                    );
                    break;
                }
                q++;
            }
        }
    }

    /* stpcpy, wcscpy, wcscat — also unbounded */
    if (find_call_args(line, "stpcpy") || find_call_args(line, "wcscpy")) {
        add_finding(
            "Buffer Overflow", "HIGH", lineno, raw,
            "stpcpy/wcscpy perform unbounded copies with no destination size check.",
            "Use bounded alternatives such as stpncpy or wcsncpy with explicit limits.",
            "CWE-120"
        );
    }
}

/* ------------------------------------------------------------------ */
/* Detector 2: Format String                                            */
/* CWE-134                                                              */
/* ------------------------------------------------------------------ */

static void detect_format_string(const char *line, int lineno,
                                 const char *raw) {
    static const struct { const char *fn; int fmt_arg; } fmtfns[] = {
        {"printf",   1}, {"fprintf",  2}, {"sprintf",  2},
        {"snprintf", 3}, {"syslog",   2}, {"vprintf",  1},
        {"vsprintf", 2}, {"err",      2}, {"warn",     1},
        {NULL, 0}
    };

    /* Input functions that taint a named buffer variable */
    static const struct { const char *fn; int taint_arg; } input_fns[] = {
        {"fgets",   1}, {"gets",    1}, {"fread",   1},
        {"getline", 1}, {"read",    2}, {"scanf",   2},
        {"fscanf",  3}, {"sscanf",  3},
        {NULL, 0}
    };

    /* --- Step A: clear taint for variables reassigned on this line --- */
    for (int i = 0; i < tainted_count; i++) {
        if (!tainted_vars[i].is_tainted) continue;
        const char *vn = tainted_vars[i].name;
        size_t vlen = strlen(vn);
        const char *p = line;
        while (*p) {
            if ((p == line || !is_ident((unsigned char)*(p-1))) &&
                strncmp(p, vn, vlen) == 0 &&
                !is_ident((unsigned char)p[vlen])) {
                const char *q = p + vlen;
                while (*q && isspace((unsigned char)*q)) q++;
                if (*q == '=' && *(q+1) != '=') {
                    tainted_vars[i].is_tainted = 0;
                    break;
                }
            }
            p++;
        }
    }

    /* --- Step B: taint variables filled by user-input functions --- */
    for (int i = 0; input_fns[i].fn; i++) {
        const char *args = find_call_args(line, input_fns[i].fn);
        if (!args) continue;
        char varname[MAX_VAR_LEN] = {0};
        extract_nth_arg(args, input_fns[i].taint_arg, varname, sizeof(varname));
        /* strip leading & / * decorators and keep only the identifier */
        const char *vp = varname;
        while (*vp == '&' || *vp == '*' || *vp == ' ') vp++;
        char clean[MAX_VAR_LEN] = {0};
        int ci = 0;
        while (*vp && is_ident(*vp) && ci < MAX_VAR_LEN - 1)
            clean[ci++] = *vp++;
        if (clean[0]) {
            TaintVar *tv = get_tainted_var(clean);
            if (tv) { tv->is_tainted = 1; tv->taint_line = lineno; }
        }
    }

    /* Handle fgetc / getchar / getc: result is assigned → `var = fgetc(...)` */
    {
        static const char *char_fns[] = { "fgetc", "getchar", "getc", NULL };
        for (int fi = 0; char_fns[fi]; fi++) {
            if (!find_call_args(line, char_fns[fi])) continue;
            /* Search backward from the function name for an assignment target */
            const char *call = strstr(line, char_fns[fi]);
            if (!call) continue;
            const char *eq = call;
            while (eq > line && *eq != '=') eq--;
            if (*eq != '=' || *(eq+1) == '=') continue;
            const char *e = eq - 1;
            while (e > line && isspace((unsigned char)*e)) e--;
            if (!is_ident((unsigned char)*e)) continue;
            const char *end = e + 1;
            while (e > line && is_ident((unsigned char)*(e-1))) e--;
            int len = (int)(end - e);
            if (len <= 0 || len >= MAX_VAR_LEN) continue;
            char vname[MAX_VAR_LEN] = {0};
            strncpy(vname, e, (size_t)len);
            TaintVar *tv = get_tainted_var(vname);
            if (tv) { tv->is_tainted = 1; tv->taint_line = lineno; }
            break;
        }
    }

    /* --- Step C: check each printf-family call on this line --- */
    for (int i = 0; fmtfns[i].fn; i++) {
        const char *args = find_call_args(line, fmtfns[i].fn);
        if (!args) continue;

        /* Advance to the Nth (format) argument */
        const char *p = args;
        for (int a = 1; a < fmtfns[i].fmt_arg; a++) {
            int depth = 0;
            while (*p) {
                if      (*p == '(')                       depth++;
                else if (*p == ')') { if (!depth) { p = NULL; break; } depth--; }
                else if (*p == ',' && !depth)             { p++; break; }
                p++;
            }
            if (!p || !*p) break;
        }
        if (!p || !*p) continue;
        while (*p && isspace((unsigned char)*p)) p++;

        if (*p == '"') {
            /* ---- Check 1: scan inside the string literal ---- */
            const char *q = p + 1;
            int spec_count = 0, xp_count = 0;

            while (*q && *q != '"') {
                if (*q == '\\') { q++; if (*q && *q != '"') q++; continue; }
                if (*q != '%')  { q++; continue; }
                q++;                        /* skip '%' */
                if (!*q || *q == '"') break;
                if (*q == '%') { q++; continue; }   /* %% — not a specifier */

                /* skip printf flags: -, +, space, #, 0 */
                while (*q && strchr("-+ #0", *q)) q++;

                /* check for positional %N$ syntax */
                if (isdigit((unsigned char)*q)) {
                    const char *d = q;
                    while (isdigit((unsigned char)*d)) d++;
                    if (*d == '$') {
                        add_finding("Format String", "HIGH", lineno, raw,
                            "Direct parameter field width syntax like `%3$n` allows an "
                            "attacker to target specific stack positions for reading or "
                            "writing. Combined with `%n` this enables precise arbitrary "
                            "memory writes.",
                            "Never use positional parameter syntax. Use a fixed string "
                            "literal with one specifier per argument in order.",
                            "CWE-134");
                        q = d + 1;      /* advance past '$' to the specifier letter */
                    } else {
                        while (isdigit((unsigned char)*q)) q++; /* skip plain width */
                    }
                }
                /* skip '*' width */
                if (*q == '*') q++;
                /* skip .precision */
                if (*q == '.') { q++; while (isdigit((unsigned char)*q) || *q=='*') q++; }
                /* skip length modifiers */
                while (*q && strchr("hlLzjt", *q)) q++;

                if (!*q || *q == '"') break;
                char spec = *q++;

                if (spec == 'n') {
                    add_finding("Format String", "HIGH", lineno, raw,
                        "`%n` writes the number of bytes printed so far into a pointer "
                        "argument. If an attacker influences this call they can write "
                        "arbitrary values to arbitrary memory addresses -- this is code "
                        "execution, not just a crash.",
                        "Remove `%n` from all format strings. There is no safe use of "
                        "`%n` in security-sensitive code.",
                        "CWE-134");
                }
                if (spec == 'x' || spec == 'X' || spec == 'p') xp_count++;
                spec_count++;
            }
            /* q now sits on the closing '"' (or end of string) */

            if (xp_count >= 2) {
                add_finding("Format String", "MEDIUM", lineno, raw,
                    "Multiple `%x` or `%p` specifiers read raw values off the stack. "
                    "If user input reaches this format string, an attacker can leak "
                    "sensitive memory contents including addresses, canaries, and pointers.",
                    "Avoid multiple %x/%p specifiers. Print specific named values "
                    "with %d/%u/%s rather than stack-scanning patterns.",
                    "CWE-134");
            }

            if (*q == '"') {
                int args_after = count_args_from(q + 1);
                if (spec_count > args_after) {
                    add_finding("Format String", "MEDIUM", lineno, raw,
                        "There are more format specifiers than arguments provided. "
                        "The printf family will read past the supplied arguments onto "
                        "the stack, potentially leaking sensitive values or causing a crash.",
                        "Ensure every format specifier has a corresponding argument. "
                        "Enable -Wformat -Wformat-extra-args to catch mismatches at "
                        "compile time.",
                        "CWE-134");
                }
            }

        } else if (*p && *p != ')' && strncmp(p, "NULL", 4) != 0) {
            /* ---- Check 2: variable as format argument ---- */

            /* Extract identifier from the format argument */
            char fmt_var[MAX_VAR_LEN] = {0};
            extract_first_arg(p, fmt_var, sizeof(fmt_var));
            const char *vp = fmt_var;
            while (*vp == '&' || *vp == '*') vp++;
            char clean_var[MAX_VAR_LEN] = {0};
            int ci = 0;
            while (*vp && is_ident(*vp) && ci < MAX_VAR_LEN - 1)
                clean_var[ci++] = *vp++;

            /* Taint check: is this variable a known user-input source? */
            int tainted = 0;
            if (clean_var[0]) {
                for (int t = 0; t < tainted_count; t++) {
                    if (tainted_vars[t].is_tainted &&
                        strcmp(tainted_vars[t].name, clean_var) == 0) {
                        char expl[MAX_EXPL_LEN], fix[MAX_FIX_LEN];
                        snprintf(expl, sizeof(expl),
                            "The format string argument comes directly from user input "
                            "collected at line %d. An attacker who controls this input "
                            "can inject format specifiers like %%n, %%x, or %%p to read "
                            "from or write to arbitrary memory addresses. This is a "
                            "classic format string attack vector.",
                            tainted_vars[t].taint_line);
                        snprintf(fix, sizeof(fix),
                            "Never use user-supplied data as a format string. "
                            "Replace with: printf(\"%%s\", %s);", clean_var);
                        add_finding("Format String", "HIGH", lineno, raw,
                                    expl, fix, "CWE-134");
                        tainted = 1;
                        break;
                    }
                }
            }

            /* Fallback: non-literal format arg even without known taint source */
            if (!tainted) {
                add_finding(
                    "Format String", "HIGH", lineno, raw,
                    "The format argument is a variable rather than a string literal. "
                    "An attacker who controls this string can use format specifiers "
                    "like %x, %n to read from or write to arbitrary memory addresses.",
                    "Always pass a string literal as the format argument, e.g., "
                    "printf(\"%s\", userInput) instead of printf(userInput).",
                    "CWE-134");
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Detector 3: Command Injection                                        */
/* CWE-78                                                               */
/* ------------------------------------------------------------------ */

static void detect_command_injection(const char *line, int lineno,
                                     const char *raw) {
    static const char *exec_fns[] = {
        "system", "popen", "execl", "execlp", "execle",
        "execv", "execvp", "execvpe", "execve",
        "wordexp", "posix_spawn",
        NULL
    };

    for (int i = 0; exec_fns[i]; i++) {
        const char *args = find_call_args(line, exec_fns[i]);
        if (!args) continue;

        char first[MAX_VAR_LEN] = {0};
        extract_first_arg(args, first, sizeof(first));
        const char *f = ltrim(first);

        /* If not a string literal -> potential injection */
        if (*f && *f != '"') {
            char expl[MAX_EXPL_LEN], fix[MAX_FIX_LEN];
            snprintf(expl, sizeof(expl),
                "%s() is called with a variable as its command argument. "
                "If any part of that string originates from user input, "
                "an attacker can inject shell metacharacters (;, |, $(), etc.) "
                "to execute arbitrary commands on the host system.",
                exec_fns[i]);
            snprintf(fix, sizeof(fix),
                "Avoid %s() with user-controlled input. If shell execution is required, "
                "validate and sanitize input strictly, or use execv()-family functions "
                "with argument arrays to prevent shell interpretation.",
                exec_fns[i]);
            add_finding("Command Injection", "HIGH", lineno, raw,
                        expl, fix, "CWE-78");
            break;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Detector 4 & 5: Use-After-Free / Double Free (multi-line)           */
/* CWE-416, CWE-415                                                     */
/* ------------------------------------------------------------------ */

/* Called on every line; maintains freed variable state */
static void detect_uaf_and_double_free(const char *line, int lineno,
                                       const char *raw) {
    /* Check for free() call */
    const char *fargs = find_call_args(line, "free");
    if (fargs) {
        char varname[MAX_VAR_LEN] = {0};
        extract_free_arg(fargs, varname, sizeof(varname));
        if (varname[0] != '\0') {
            VarState *v = get_var(varname);
            if (v) {
                if (v->is_freed) {
                    /* Double free */
                    char expl[MAX_EXPL_LEN], fix[MAX_FIX_LEN];
                    snprintf(expl, sizeof(expl),
                        "The pointer '%s' was already freed at line %d. "
                        "Freeing it a second time corrupts the heap allocator's "
                        "internal metadata and can be exploited to gain arbitrary "
                        "code execution via heap-manipulation techniques.",
                        varname, v->freed_line);
                    snprintf(fix, sizeof(fix),
                        "Set the pointer to NULL immediately after the first free(): "
                        "%s = NULL; — subsequent free(NULL) is a safe no-op. "
                        "Alternatively, use a wrapper that zeroes the pointer.",
                        varname);
                    add_finding("Double Free", "HIGH", lineno, raw,
                                expl, fix, "CWE-415");
                } else {
                    v->is_freed   = 1;
                    v->freed_line = lineno;
                }
            }
        }
        return; /* don't also check UAF on the free() line itself */
    }

    /* Check if any freed variable is used on this line */
    for (int i = 0; i < var_count; i++) {
        if (!vars[i].is_freed) continue;
        const char *vn = vars[i].name;
        if (var_used_in_line(line, vn)) {
            /* Make sure this isn't another free() line - already handled */
            char expl[MAX_EXPL_LEN], fix[MAX_FIX_LEN];
            snprintf(expl, sizeof(expl),
                "Pointer '%s' was freed at line %d but is accessed here. "
                "The memory it points to may have been reallocated and "
                "overwritten, causing undefined behaviour, data corruption, "
                "or an exploitable use-after-free condition.",
                vn, vars[i].freed_line);
            snprintf(fix, sizeof(fix),
                "Set '%s = NULL' immediately after free(). "
                "Add a NULL-check before any subsequent dereference, "
                "or redesign ownership so the pointer is not accessible "
                "after its lifetime ends.",
                vn);
            add_finding("Use-After-Free", "HIGH", lineno, raw,
                        expl, fix, "CWE-416");
        }
    }

    /* Reset freed flag if the variable is reassigned (= malloc / = NULL / etc.) */
    for (int i = 0; i < var_count; i++) {
        if (!vars[i].is_freed) continue;
        /* Look for: varname = something */
        const char *p = line;
        size_t vlen = strlen(vars[i].name);
        while (*p) {
            if ((p == line || !is_ident((unsigned char)*(p-1))) &&
                strncmp(p, vars[i].name, vlen) == 0) {
                const char *q = p + vlen;
                while (*q && isspace((unsigned char)*q)) q++;
                if (*q == '=') {
                    vars[i].is_freed = 0;
                    break;
                }
            }
            p++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Detector 6: TOCTTOU (Time-of-Check Time-of-Use)                     */
/* CWE-367                                                              */
/* ------------------------------------------------------------------ */

static void detect_tocttou(const char *line, int lineno, const char *raw) {
    /* Step 1: detect access() or stat() calls and record the path variable */
    static const char *check_fns[] = { "access", "stat", "lstat", "faccessat", NULL };
    static const char *use_fns[]   = { "fopen", "open", "creat", "openat",
                                       "execve", "execl", "rename", "unlink",
                                       "chmod", "chown", NULL };

    for (int i = 0; check_fns[i]; i++) {
        const char *args = find_call_args(line, check_fns[i]);
        if (!args) continue;
        char pathvar[MAX_VAR_LEN] = {0};
        extract_first_arg(args, pathvar, sizeof(pathvar));
        if (pathvar[0] == '\0') continue;
        VarState *v = get_var(pathvar);
        if (v) {
            v->is_path_checked = 1;
            v->check_line = lineno;
        }
    }

    /* Step 2: detect use of a previously checked path */
    for (int i = 0; use_fns[i]; i++) {
        const char *args = find_call_args(line, use_fns[i]);
        if (!args) continue;
        char pathvar[MAX_VAR_LEN] = {0};
        extract_first_arg(args, pathvar, sizeof(pathvar));
        if (pathvar[0] == '\0') continue;
        VarState *v = get_var(pathvar);
        if (v && v->is_path_checked && v->check_line != lineno) {
            char expl[MAX_EXPL_LEN], fix[MAX_FIX_LEN];
            snprintf(expl, sizeof(expl),
                "The path '%s' was checked at line %d with %s() but is used here "
                "with %s(). Between the check and the use, a race condition exists: "
                "an attacker can replace the file (e.g. with a symlink) after the "
                "check passes, forcing the program to operate on an unintended target.",
                pathvar, v->check_line, check_fns[i], use_fns[i]);
            snprintf(fix, sizeof(fix),
                "Eliminate the TOCTOU window: open the file first with open() "
                "using O_NOFOLLOW, then use fstat() on the returned fd to verify "
                "its properties. Never rely on access() for security decisions.");
            add_finding("TOCTTOU", "MEDIUM", lineno, raw,
                        expl, fix, "CWE-367");
            /* reset so we don't re-fire on the same var multiple times */
            v->is_path_checked = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* JSON output                                                          */
/* ------------------------------------------------------------------ */

static void print_json(void) {
    printf("{\n  \"findings\": [");
    for (int i = 0; i < finding_count; i++) {
        Finding *f = &findings[i];
        char snippet[MAX_SNIPPET_LEN*2];
        char explanation[MAX_EXPL_LEN*2];
        char fix[MAX_FIX_LEN*2];
        json_escape(f->snippet,     snippet,     sizeof(snippet));
        json_escape(f->explanation, explanation, sizeof(explanation));
        json_escape(f->fix,         fix,         sizeof(fix));

        printf("%s\n    {\n", i == 0 ? "" : ",");
        printf("      \"type\": \"%s\",\n",        f->type);
        printf("      \"severity\": \"%s\",\n",    f->severity);
        printf("      \"line\": %d,\n",            f->line);
        printf("      \"snippet\": \"%s\",\n",     snippet);
        printf("      \"explanation\": \"%s\",\n", explanation);
        printf("      \"fix\": \"%s\",\n",         fix);
        printf("      \"cwe\": \"%s\"\n",          f->cwe);
        printf("    }");
    }
    printf("\n  ]\n}\n");
}

/* ------------------------------------------------------------------ */
/* Main                                                                 */
/* ------------------------------------------------------------------ */

static void analyze_lines(char lines[][MAX_LINE_LEN], int count) {
    for (int i = 0; i < count; i++) {
        const char *raw  = lines[i];
        /* working copy lower-trimmed */
        char lc[MAX_LINE_LEN];
        strncpy(lc, raw, MAX_LINE_LEN - 1);
        lc[MAX_LINE_LEN - 1] = '\0';

        int lineno = i + 1;

        detect_buffer_overflow(lc, lineno, raw);
        detect_format_string(lc, lineno, raw);
        detect_command_injection(lc, lineno, raw);
        detect_uaf_and_double_free(lc, lineno, raw);
        detect_tocttou(lc, lineno, raw);
    }
}

int main(int argc, char *argv[]) {
    FILE *fp = NULL;
    int   from_stdin = 0;

    if (argc >= 2) {
        if (strcmp(argv[1], "--stdin") == 0 || strcmp(argv[1], "-") == 0) {
            fp = stdin;
            from_stdin = 1;
        } else {
            fp = fopen(argv[1], "r");
            if (!fp) {
                fprintf(stderr, "vulncheck: cannot open '%s'\n", argv[1]);
                /* return clean JSON with error note */
                printf("{\"error\": \"cannot open file\", \"findings\": []}\n");
                return 1;
            }
        }
    } else {
        fp = stdin;
        from_stdin = 1;
    }

    /* Read all lines */
    static char lines[MAX_LINES][MAX_LINE_LEN];
    int count = 0;
    while (count < MAX_LINES && fgets(lines[count], MAX_LINE_LEN, fp)) {
        /* strip newline */
        int len = strlen(lines[count]);
        while (len > 0 && (lines[count][len-1] == '\n' ||
                            lines[count][len-1] == '\r')) {
            lines[count][--len] = '\0';
        }
        count++;
    }

    if (!from_stdin) fclose(fp);

    analyze_lines(lines, count);
    print_json();
    return 0;
}
