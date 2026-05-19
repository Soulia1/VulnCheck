const { useState, useEffect, useMemo, useRef, useCallback, useId } = React;

/* ------------------------------------------------------------------ */
/* Etheral Shadow — adapted from 21st.dev (framer-motion → rAF)        */
/* ------------------------------------------------------------------ */

function mapRange(value, fromLow, fromHigh, toLow, toHigh) {
  if (fromLow === fromHigh) return toLow;
  return toLow + ((value - fromLow) / (fromHigh - fromLow)) * (toHigh - toLow);
}

function EtheralShadow({
  sizing = 'fill',
  color = 'rgba(128,128,128,1)',
  animation,
  noise,
  style,
  className,
}) {
  const rawId = useId().replace(/:/g, '');
  const filterId = `etheral-${rawId}`;
  const matrixRef = useRef(null);

  const animationEnabled = animation && animation.scale > 0;
  const displacementScale = animation ? mapRange(animation.scale, 1, 100, 20, 100) : 0;
  const animationDuration = animation ? mapRange(animation.speed, 1, 100, 1000, 50) : 1;

  useEffect(() => {
    if (!animationEnabled || !matrixRef.current) return;
    const totalMs = (animationDuration / 25) * 1000;
    let raf, start;
    const tick = (t) => {
      if (start == null) start = t;
      const v = (((t - start) % totalMs) / totalMs) * 360;
      if (matrixRef.current) matrixRef.current.setAttribute('values', String(v));
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [animationEnabled, animationDuration]);

  const maskUrl = "url('assets/shadow-mask.png')";

  return (
    <div
      className={className}
      style={{ overflow: 'hidden', position: 'relative', width: '100%', height: '100%', ...style }}
    >
      <div
        style={{
          position: 'absolute',
          inset: -displacementScale,
          filter: animationEnabled ? `url(#${filterId}) blur(4px)` : 'none',
        }}
      >
        {animationEnabled && (
          <svg style={{ position: 'absolute' }}>
            <defs>
              <filter id={filterId}>
                <feTurbulence
                  result="undulation"
                  numOctaves="2"
                  baseFrequency={`${mapRange(animation.scale, 0, 100, 0.001, 0.0005)},${mapRange(animation.scale, 0, 100, 0.004, 0.002)}`}
                  seed="0"
                  type="turbulence"
                />
                <feColorMatrix ref={matrixRef} in="undulation" type="hueRotate" values="180" />
                <feColorMatrix
                  in="dist"
                  result="circulation"
                  type="matrix"
                  values="4 0 0 0 1  4 0 0 0 1  4 0 0 0 1  1 0 0 0 0"
                />
                <feDisplacementMap in="SourceGraphic" in2="circulation" scale={displacementScale} result="dist" />
                <feDisplacementMap in="dist" in2="undulation" scale={displacementScale} result="output" />
              </filter>
            </defs>
          </svg>
        )}
        <div
          style={{
            backgroundColor: color,
            maskImage: maskUrl,
            WebkitMaskImage: maskUrl,
            maskSize: sizing === 'stretch' ? '100% 100%' : 'cover',
            WebkitMaskSize: sizing === 'stretch' ? '100% 100%' : 'cover',
            maskRepeat: 'no-repeat',
            WebkitMaskRepeat: 'no-repeat',
            maskPosition: 'center',
            WebkitMaskPosition: 'center',
            width: '100%',
            height: '100%',
          }}
        />
      </div>

      {noise && noise.opacity > 0 && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage: `url("assets/shadow-noise.png")`,
            backgroundSize: noise.scale * 200,
            backgroundRepeat: 'repeat',
            opacity: noise.opacity / 2,
          }}
        />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

const SAMPLE_CODE = `#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void greet(const char *name) {
    char buf[32];
    strcpy(buf, name);                  // user input copied without bounds
    printf(name);                       // user input as format string
    printf("Hello, %s\\n", buf);
}

int handle(int argc, char *argv[]) {
    char *cmd = malloc(128);
    sprintf(cmd, "ls -la %s", argv[1]); // unsanitized shell input
    system(cmd);

    free(cmd);
    printf("ran: %s\\n", cmd);          // use-after-free

    if (access("/tmp/data.log", R_OK) == 0) {
        FILE *f = fopen("/tmp/data.log", "r");   // TOCTTOU between check & open
        // ...
        fclose(f);
    }
    return 0;
}
`;

const PYTHON_SAMPLE_CODE = `import ctypes, os, logging

libc = ctypes.CDLL("libc.so.6")

def process(user_size, user_path, user_cmd, msg):
    buf = ctypes.create_string_buffer(user_size)  # buffer overflow: variable size

    logging.warning(msg)                           # format string: user input as format

    os.system("generate_report " + user_cmd)      # command injection: unsanitized shell input

    ptr = libc.malloc(64)
    libc.free(ptr)
    libc.strlen(ptr)                              # use-after-free: access after free()

    p = libc.malloc(32)
    libc.free(p)
    libc.free(p)                                  # double free: freed twice

    if os.access(user_path, os.R_OK):
        with open(user_path) as f:               # TOCTTOU: check then use race
            return f.read()
`;

const LANGUAGES = [
  { id: 'c',      label: 'C'      },
  { id: 'python', label: 'Python' },
];

const SEVERITY = {
  HIGH:   { label: 'HIGH',   color: '#FF5577', tint: 'rgba(255,85,119,0.10)',  text: '#FFB7C5', glow: 'glow-high', hair: 'top-hair-high' },
  MEDIUM: { label: 'MEDIUM', color: '#FFB547', tint: 'rgba(255,181,71,0.10)',  text: '#FFDFAA', glow: 'glow-med',  hair: 'top-hair-med'  },
  LOW:    { label: 'LOW',    color: '#5EC7FF', tint: 'rgba(94,199,255,0.10)',  text: '#B0E0FF', glow: 'glow-low',  hair: 'top-hair-low'  },
};

const VULN_TYPES = [
  'Buffer Overflow',
  'Format String',
  'Command Injection',
  'Use-After-Free',
  'Double Free',
  'TOCTTOU',
];

const CWE_DATA = [
  {
    id: 'CWE-120', type: 'Buffer Overflow', sev: 'HIGH',
    name: 'Buffer Copy Without Checking Size',
    desc: 'Copies data into a buffer without verifying it fits, overwriting adjacent memory.',
    trigger: 'strcpy, strcat, gets, sprintf with unchecked destination size',
    fix: 'Use strncpy, strlcpy, snprintf, or C11 strcpy_s with explicit size bounds.',
  },
  {
    id: 'CWE-134', type: 'Format String', sev: 'HIGH',
    name: 'Uncontrolled Format String',
    desc: 'Passes user-controlled data as the format argument, enabling memory reads and writes.',
    trigger: 'printf(userInput), fprintf(f, userInput), syslog(level, userInput)',
    fix: 'Always use a literal format string: printf("%s", input) instead of printf(input).',
  },
  {
    id: 'CWE-78', type: 'Command Injection', sev: 'HIGH',
    name: 'OS Command Injection',
    desc: 'Embeds unsanitised user input in a shell command, allowing arbitrary command execution.',
    trigger: 'system(), popen(), exec* family with string-built commands',
    fix: 'Avoid shell functions; use execve() with separate argv[] and validate every argument.',
  },
  {
    id: 'CWE-416', type: 'Use-After-Free', sev: 'HIGH',
    name: 'Use After Free',
    desc: 'Reads or writes memory after it has been freed, causing undefined behaviour or code execution.',
    trigger: 'Any dereference of a pointer after free(ptr)',
    fix: 'Set pointers to NULL immediately after free(); use ownership patterns or smart-pointer wrappers.',
  },
  {
    id: 'CWE-415', type: 'Double Free', sev: 'HIGH',
    name: 'Double Free',
    desc: 'Frees the same heap allocation twice, corrupting allocator metadata.',
    trigger: 'Two calls to free() on the same pointer without an intervening allocation',
    fix: 'Set ptr = NULL after the first free(); guard all frees with if (ptr) { free(ptr); ptr = NULL; }',
  },
  {
    id: 'CWE-367', type: 'TOCTTOU', sev: 'MEDIUM',
    name: 'Time-of-Check Time-of-Use Race',
    desc: 'A race condition between checking a resource (e.g. access()) and acting on it (e.g. open()).',
    trigger: 'access() / stat() followed by open() / fopen() on the same path',
    fix: 'Open the file first with O_NOFOLLOW and check permission via the file descriptor, not the path.',
  },
];

const SCAN_MESSAGES = [
  'tokenizing source',
  'building AST',
  'tracing data flow',
  'matching CWE patterns',
  'inspecting allocations',
  'auditing format strings',
  'evaluating taint paths',
  'compiling findings',
];

/* ------------------------------------------------------------------ */
/* Icons                                                                */
/* ------------------------------------------------------------------ */

const I = {
  shield: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <path d="M12 2.5L3.5 6v6c0 5 3.5 8.5 8.5 10 5-1.5 8.5-5 8.5-10V6L12 2.5z" stroke="currentColor" strokeWidth="1.5"/>
      <path d="M8.5 12.2l2.4 2.4 4.6-4.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  bolt: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
    </svg>
  ),
  check: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <path d="M5 12.5l4.5 4.5L19 7" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  warn: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <path d="M12 9v4M12 17h.01M3.5 18l8-13.5a1 1 0 011.7 0L21 18a1 1 0 01-.85 1.5h-16A1 1 0 013.5 18z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round"/>
    </svg>
  ),
  bug: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <rect x="7" y="7" width="10" height="12" rx="5" stroke="currentColor" strokeWidth="1.5"/>
      <path d="M9 5l1 2M15 5l-1 2M4 11h3M17 11h3M4 15h3M17 15h3M4 19h3M17 19h3M12 11v8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    </svg>
  ),
  arrowR: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <path d="M5 12h14m0 0l-5-5m5 5l-5 5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  copy: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <rect x="8" y="8" width="12" height="12" rx="2" stroke="currentColor" strokeWidth="1.5"/>
      <path d="M16 8V5a1 1 0 00-1-1H5a1 1 0 00-1 1v10a1 1 0 001 1h3" stroke="currentColor" strokeWidth="1.5"/>
    </svg>
  ),
  reset: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <path d="M4 4v6h6M20 20v-6h-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M20 10A8 8 0 006 6M4 14a8 8 0 0014 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    </svg>
  ),
  fix: (p) => (
    <svg viewBox="0 0 24 24" fill="none" {...p}>
      <path d="M14.7 6.3a4 4 0 00-5.6 5.6L4 17v3h3l5.1-5.1a4 4 0 005.6-5.6l-3 3-2-2 3-3z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
    </svg>
  ),
};

/* ------------------------------------------------------------------ */
/* Tooltip                                                              */
/* ------------------------------------------------------------------ */

function Tooltip({ text, children, side = 'top' }) {
  const pos = {
    top:    'bottom-full left-1/2 -translate-x-1/2 mb-2',
    bottom: 'top-full left-1/2 -translate-x-1/2 mt-2',
    right:  'left-full top-1/2 -translate-y-1/2 ml-2',
    left:   'right-full top-1/2 -translate-y-1/2 mr-2',
  }[side] ?? 'bottom-full left-1/2 -translate-x-1/2 mb-2';
  return (
    <div className="relative group/tt inline-flex">
      {children}
      <span className={`absolute ${pos} z-50 pointer-events-none opacity-0 group-hover/tt:opacity-100 transition-opacity duration-150 px-2 py-1 rounded-md bg-[#080F1F] border border-[var(--bd-2)] font-mono text-[10px] text-[var(--ink-0)] whitespace-nowrap shadow-xl`}>
        {text}
      </span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Skeleton Loaders                                                     */
/* ------------------------------------------------------------------ */

function Skeleton({ className = '' }) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse rounded-md bg-[rgba(164,174,203,0.16)] ${className}`}
    />
  );
}

function SkeletonDemo() {
  return (
    <div className="flex items-center gap-4">
      <Skeleton className="h-12 w-12 shrink-0 rounded-full" />
      <div className="min-w-0 flex-1 space-y-2">
        <Skeleton className="h-4 w-full max-w-[250px]" />
        <Skeleton className="h-4 w-full max-w-[200px]" />
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Count-up animation hook                                              */
/* ------------------------------------------------------------------ */

function useCountUp(target, duration = 550) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (target === 0) { setVal(0); return; }
    let raf;
    const t0 = performance.now();
    const tick = (now) => {
      const p = Math.min((now - t0) / duration, 1);
      setVal(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return val;
}

/* ------------------------------------------------------------------ */
/* CWE Catalog Section                                                  */
/* ------------------------------------------------------------------ */

function CweCatalogSection() {
  return (
    <div className="relative z-10 max-w-[1400px] mx-auto px-6 pb-24 pt-6">
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <span className="w-1 h-4 bg-[var(--accent)]" style={{boxShadow: '0 0 12px var(--accent)'}}></span>
          <h2 className="font-display font-semibold text-[15px] tracking-tight uppercase">CWE Catalog</h2>
          <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">— {CWE_DATA.length} patterns covered</span>
        </div>
        <p className="text-[13.5px] text-[var(--ink-1)] max-w-[680px] leading-relaxed">
          VulnCheck maps every finding to a CWE identifier. The patterns below are the six vulnerability classes the engine detects in C and Python source code.
        </p>
      </div>
      <div className="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
        {CWE_DATA.map(entry => {
          const s = SEVERITY[entry.sev] || SEVERITY.LOW;
          return (
            <div key={entry.id} className={`panel relative overflow-hidden ${s.glow} p-5`}>
              <div className={`absolute inset-x-0 top-0 h-px ${s.hair}`}></div>
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-[var(--bg-2)] border border-[var(--bd-1)] text-[var(--ink-1)]">{entry.id}</span>
                <SeverityBadge sev={entry.sev} />
              </div>
              <h3 className="font-display font-semibold text-[17px] tracking-tight mb-1">{entry.name}</h3>
              <p className="text-[13px] text-[var(--ink-1)] leading-relaxed mb-4">{entry.desc}</p>
              <div className="space-y-2.5 border-t border-[var(--bd-1)] pt-3">
                <div>
                  <div className="font-mono text-[9px] uppercase tracking-wider text-[var(--ink-2)] mb-1">triggers on</div>
                  <div className="font-mono text-[11px] text-[var(--ink-1)] bg-[var(--bg-1)] rounded px-2 py-1.5 border border-[var(--bd-1)]">{entry.trigger}</div>
                </div>
                <div>
                  <div className="font-mono text-[9px] uppercase tracking-wider text-[var(--accent)] mb-1">suggested fix</div>
                  <div className="text-[12.5px] text-[var(--ink-1)] leading-relaxed">{entry.fix}</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Lessons Section                                                      */
/* ------------------------------------------------------------------ */

const LESSONS_DATA = [
  {
    type: 'Buffer Overflow', cwe: 'CWE-120', sev: 'HIGH',
    what: 'A buffer overflow occurs when a program writes more data into a fixed-size buffer than it can hold, corrupting adjacent memory regions.',
    why: 'Attackers can overwrite return addresses or function pointers to redirect execution, leading to arbitrary code execution or privilege escalation.',
    vuln: `char buf[32];\nstrcpy(buf, argv[1]);  // argv[1] can be > 32 bytes`,
    safe: `char buf[32];\nstrncpy(buf, argv[1], sizeof(buf) - 1);\nbuf[sizeof(buf) - 1] = '\\0';`,
  },
  {
    type: 'Format String', cwe: 'CWE-134', sev: 'HIGH',
    what: 'A format string vulnerability arises when user-supplied data is passed directly as the format argument to printf-family functions.',
    why: 'Attackers can use %x/%n specifiers to read stack values or write arbitrary data to memory locations, enabling information disclosure or code execution.',
    vuln: `printf(user_input);          // dangerous\nfprintf(log_file, user_input); // also dangerous`,
    safe: `printf("%s", user_input);         // safe\nfprintf(log_file, "%s", user_input); // safe`,
  },
  {
    type: 'Command Injection', cwe: 'CWE-78', sev: 'HIGH',
    what: 'Command injection lets attackers execute arbitrary OS commands by embedding shell metacharacters in input passed to system() or popen().',
    why: 'The child process runs with the same privileges as the server, so an attacker can read secrets, install backdoors, or pivot to internal services.',
    vuln: `char cmd[256];\nsprintf(cmd, "ls %s", user_path);\nsystem(cmd);  // "ls /; rm -rf /" works`,
    safe: `// Use execve() with separate args — no shell involved\nchar *args[] = { "ls", user_path, NULL };\nexecv("/bin/ls", args);`,
  },
  {
    type: 'Use-After-Free', cwe: 'CWE-416', sev: 'HIGH',
    what: 'Use-After-Free (UAF) occurs when code continues to use a pointer after the memory it points to has been freed back to the heap.',
    why: 'An allocator may reuse the freed region for a different object. Accessing the stale pointer can corrupt that object or, if attacker-controlled, execute arbitrary code.',
    vuln: `char *buf = malloc(64);\nfree(buf);\nprintf("%s", buf); // undefined — heap may be reused`,
    safe: `char *buf = malloc(64);\nfree(buf);\nbuf = NULL;        // NULL-out immediately\n// any access now faults visibly`,
  },
  {
    type: 'Double Free', cwe: 'CWE-415', sev: 'HIGH',
    what: 'Double Free happens when free() is called twice on the same heap pointer, corrupting the allocator\'s internal free-list.',
    why: 'A corrupted free-list can be exploited to make the next malloc() return an attacker-chosen address, enabling arbitrary writes.',
    vuln: `char *p = malloc(32);\nfree(p);\n// ... later in error path ...\nfree(p);  // second free — heap corruption`,
    safe: `char *p = malloc(32);\nfree(p);\np = NULL;          // guard against double-free\n// safe: free(NULL) is a no-op`,
  },
  {
    type: 'TOCTTOU', cwe: 'CWE-367', sev: 'MEDIUM',
    what: 'Time-of-Check Time-of-Use is a race condition between verifying a resource (e.g. access()) and then acting on it (e.g. open()).',
    why: 'An attacker can swap the target file with a symlink between the check and the use, bypassing the access control and accessing privileged files.',
    vuln: `if (access(path, R_OK) == 0) {\n    // attacker swaps symlink here\n    FILE *f = fopen(path, "r"); // opens attacker file\n}`,
    safe: `// Open first, then check via fd — no race window\nint fd = open(path, O_RDONLY | O_NOFOLLOW);\nif (fd >= 0) { /* use fd, not path */ }`,
  },
];

function LessonsSection() {
  const [open, setOpen] = useState(null);
  return (
    <div className="relative z-10 max-w-[1400px] mx-auto px-6 pb-24 pt-6">
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <span className="w-1 h-4 bg-[var(--azure)]" style={{boxShadow: '0 0 12px var(--azure)'}}></span>
          <h2 className="font-display font-semibold text-[15px] tracking-tight uppercase">Lessons</h2>
          <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">— {LESSONS_DATA.length} vulnerability classes</span>
        </div>
        <p className="text-[13.5px] text-[var(--ink-1)] max-w-[680px] leading-relaxed">
          Click a lesson to expand its explanation, see a vulnerable code example, and learn the safe pattern to apply.
        </p>
      </div>
      <div className="space-y-3 max-w-[860px]">
        {LESSONS_DATA.map((lesson, idx) => {
          const s = SEVERITY[lesson.sev] || SEVERITY.LOW;
          const isOpen = open === idx;
          return (
            <div key={idx} className={`panel relative overflow-hidden transition-all`} style={{borderColor: isOpen ? s.color + '44' : ''}}>
              <div className={`absolute inset-x-0 top-0 h-px`} style={{background: isOpen ? `linear-gradient(90deg, transparent, ${s.color}, transparent)` : 'none'}}></div>
              <button
                className="w-full flex items-center justify-between p-5 text-left"
                onClick={() => setOpen(isOpen ? null : idx)}
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-[11px] text-[var(--ink-2)] w-5">{String(idx + 1).padStart(2,'0')}</span>
                  <span className="font-display font-semibold text-[17px]">{lesson.type}</span>
                  <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[var(--bg-2)] border border-[var(--bd-1)] text-[var(--ink-2)]">{lesson.cwe}</span>
                  <SeverityBadge sev={lesson.sev} />
                </div>
                <svg viewBox="0 0 24 24" className={`w-4 h-4 text-[var(--ink-2)] transition-transform shrink-0 ${isOpen ? 'rotate-180' : ''}`} fill="none">
                  <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              </button>
              {isOpen && (
                <div className="px-5 pb-5 border-t border-[var(--bd-1)] pt-4 space-y-4">
                  <p className="text-[13.5px] text-[var(--ink-1)] leading-relaxed">{lesson.what}</p>
                  <div className="bg-[rgba(255,85,119,0.07)] border border-[var(--sev-high)]/20 rounded-lg p-3.5">
                    <div className="font-mono text-[9px] uppercase tracking-wider text-[var(--sev-high)] mb-1.5">why it's dangerous</div>
                    <p className="text-[13px] text-[var(--ink-1)] leading-relaxed">{lesson.why}</p>
                  </div>
                  <div className="grid md:grid-cols-2 gap-3">
                    <div>
                      <div className="font-mono text-[9px] uppercase tracking-wider text-[var(--sev-high)] mb-1.5">vulnerable pattern</div>
                      <pre className="font-mono text-[12px] leading-relaxed bg-[var(--bg-1)] border border-[var(--sev-high)]/25 rounded-lg p-3.5 whitespace-pre-wrap text-[#DCE3F5]">{lesson.vuln}</pre>
                    </div>
                    <div>
                      <div className="font-mono text-[9px] uppercase tracking-wider text-[var(--accent)] mb-1.5">safe pattern</div>
                      <pre className="font-mono text-[12px] leading-relaxed bg-[var(--bg-1)] border border-[var(--accent)]/25 rounded-lg p-3.5 whitespace-pre-wrap text-[#DCE3F5]">{lesson.safe}</pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Docs Section                                                         */
/* ------------------------------------------------------------------ */

function DocsSection() {
  return (
    <div className="relative z-10 max-w-[1400px] mx-auto px-6 pb-24 pt-6">
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <span className="w-1 h-4 bg-[var(--sev-med)]" style={{boxShadow: '0 0 12px var(--sev-med)'}}></span>
          <h2 className="font-display font-semibold text-[15px] tracking-tight uppercase">Docs</h2>
          <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">— api & usage reference</span>
        </div>
      </div>
      <div className="grid md:grid-cols-2 gap-6 max-w-[1000px]">
        {/* Usage */}
        <div className="panel p-5 space-y-4">
          <h3 className="font-display font-semibold text-[17px]">Using the Scanner</h3>
          <ol className="space-y-3 text-[13.5px] text-[var(--ink-1)] leading-relaxed list-none">
            {[
              ['01', 'Paste or type C source code in the editor, or click Upload .C to load a file.'],
              ['02', 'Press Analyze Code or hit Ctrl+Enter to submit to the engine.'],
              ['03', 'Findings appear on the right — each card shows severity, CWE ID, the vulnerable snippet, an explanation and a suggested fix.'],
              ['04', 'The safety score (0–100) decreases with each finding weighted by severity.'],
            ].map(([n, text]) => (
              <li key={n} className="flex gap-3">
                <span className="font-mono text-[10px] text-[var(--ink-2)] mt-1 shrink-0">[{n}]</span>
                <span>{text}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* Engine */}
        <div className="panel p-5 space-y-4">
          <h3 className="font-display font-semibold text-[17px]">Analysis Engine</h3>
          <div className="space-y-2.5 text-[13.5px] text-[var(--ink-1)] leading-relaxed">
            <p>Two engines power the analysis: a compiled C binary (<code className="font-mono text-[12px] bg-[var(--bg-2)] px-1.5 py-0.5 rounded border border-[var(--bd-1)]">vulncheck</code>) for C code, and a Python script (<code className="font-mono text-[12px] bg-[var(--bg-2)] px-1.5 py-0.5 rounded border border-[var(--bd-1)]">vulncheck_python.py</code>) for Python code.</p>
            <p>Each engine performs pattern-based and taint-aware static analysis and outputs structured JSON.</p>
          </div>
          <div className="font-mono text-[9px] uppercase tracking-wider text-[var(--ink-2)] mt-3 mb-1.5">supported patterns</div>
          <div className="flex flex-wrap gap-1.5">
            {VULN_TYPES.map(v => (
              <span key={v} className="font-mono text-[10px] px-2 py-0.5 rounded border border-[var(--bd-1)] bg-[var(--bg-1)] text-[var(--ink-1)]">{v}</span>
            ))}
          </div>
        </div>

        {/* REST API */}
        <div className="panel p-5 space-y-4 md:col-span-2">
          <h3 className="font-display font-semibold text-[17px]">REST API</h3>
          <div className="grid md:grid-cols-3 gap-4">
            {[
              {
                method: 'POST', path: '/analyze',
                desc: 'Analyse source code submitted as JSON.',
                body: '{ "code": "<source>", "language": "c | python" }',
              },
              {
                method: 'POST', path: '/analyze/upload',
                desc: 'Analyse a .c file uploaded as multipart/form-data.',
                body: 'FormData field: file (.c file, max 1 MB)',
              },
              {
                method: 'GET', path: '/health',
                desc: 'Returns engine status and current port.',
                body: '{ "status": "ok", "engine": "ready", "port": 3000 }',
              },
            ].map(ep => (
              <div key={ep.path} className="bg-[var(--bg-1)] border border-[var(--bd-1)] rounded-lg p-4 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-[var(--accent)]/15 border border-[var(--accent)]/30 text-[var(--accent)]">{ep.method}</span>
                  <code className="font-mono text-[12px] text-[var(--ink-0)]">{ep.path}</code>
                </div>
                <p className="text-[12.5px] text-[var(--ink-1)] leading-relaxed">{ep.desc}</p>
                <div className="font-mono text-[10px] text-[var(--ink-2)] bg-[var(--bg-0)] rounded px-2 py-1.5 border border-[var(--bd-1)]">{ep.body}</div>
              </div>
            ))}
          </div>
          <div>
            <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)] mb-2">response schema</div>
            <pre className="font-mono text-[12px] leading-relaxed bg-[var(--bg-0)] border border-[var(--bd-1)] rounded-lg p-4 text-[#DCE3F5] overflow-x-auto">{`{
  "findings": [
    {
      "type":        "Buffer Overflow",   // vulnerability class
      "severity":    "HIGH",              // HIGH | MEDIUM | LOW
      "line":        7,                   // source line number
      "snippet":     "strcpy(buf, name)", // flagged code
      "cwe":         "CWE-120",
      "explanation": "...",
      "fix":         "..."
    }
  ]
}`}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Background                                                           */
/* ------------------------------------------------------------------ */

function Background() {
  return (
    <div aria-hidden className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
      {/* base dark wash */}
      <div className="absolute inset-0" style={{ background: 'var(--bg-0)' }}></div>

      {/* Etheral Shadow — tinted to harmonize with navy panels */}
      <div className="absolute inset-0">
        <EtheralShadow
          sizing="fill"
          color="rgba(110, 140, 190, 1)"
          animation={{ scale: 100, speed: 90 }}
          noise={{ opacity: 0.6, scale: 1.2 }}
        />
      </div>

      {/* mint chromatic accent — slow, subtle */}
      <div className="absolute inset-0" style={{ opacity: 0.45, mixBlendMode: 'screen' }}>
        <EtheralShadow
          sizing="fill"
          color="rgba(124, 255, 205, 0.55)"
          animation={{ scale: 70, speed: 50 }}
          noise={{ opacity: 0, scale: 1 }}
        />
      </div>

      {/* subtle vignette so panel text remains legible at edges */}
      <div className="absolute inset-0" style={{
        background: 'radial-gradient(ellipse 90% 70% at 50% 40%, transparent 0%, rgba(6,8,15,0.35) 70%, rgba(6,8,15,0.7) 100%)'
      }}></div>

      {/* very faint grid for tech texture */}
      <div className="absolute inset-0 grid-bg" style={{ opacity: 0.35 }}></div>

      {/* horizon line */}
      <div className="absolute left-0 right-0 top-[420px] h-px bg-gradient-to-r from-transparent via-[rgba(94,199,255,0.18)] to-transparent"></div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Logo + Header                                                        */
/* ------------------------------------------------------------------ */

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative w-9 h-9 grid place-items-center rounded-md border border-[var(--bd-2)] bg-[var(--bg-2)] overflow-hidden">
        <div className="absolute inset-0 opacity-50" style={{background: 'radial-gradient(circle at 30% 20%, rgba(124,255,205,0.35), transparent 60%)'}}></div>
        <I.shield className="w-4 h-4 text-[var(--accent)] relative" />
        <span className="absolute -bottom-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-[var(--accent)] shadow-[0_0_10px_var(--accent)]"></span>
      </div>
      <div className="leading-none">
        <div className="font-display font-semibold text-[18px] tracking-tight">
          Vuln<span className="text-[var(--accent)]">Check</span>
        </div>
        <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-[var(--ink-2)] mt-1">v2.4 · static analysis</div>
      </div>
    </div>
  );
}

function Header({ activeTab, setActiveTab }) {
  return (
    <header className="relative z-20 border-b border-[var(--bd-1)] bg-[rgba(11,16,32,0.55)] backdrop-blur-xl">
      <div className="max-w-[1400px] mx-auto px-6 h-14 flex items-center justify-between">
        <Logo />
        <nav className="hidden md:flex items-center gap-0.5 font-mono text-[11px] uppercase tracking-wider">
          {['scanner','cwe catalog','lessons','docs'].map((x) => (
            <button
              key={x}
              onClick={() => setActiveTab(x)}
              className={`px-3 py-1.5 rounded-md transition ${activeTab === x ? 'text-[var(--ink-0)] bg-[var(--bg-2)] border border-[var(--bd-1)]' : 'text-[var(--ink-2)] hover:text-[var(--ink-0)]'}`}
            >{x}</button>
          ))}
        </nav>
      </div>
    </header>
  );
}

/* ------------------------------------------------------------------ */
/* Hero                                                                 */
/* ------------------------------------------------------------------ */

function Hero() {
  return (
    <section className="relative z-10">
      <div className="max-w-[1400px] mx-auto px-6 pt-14 pb-10">
        <h1 className="font-display font-semibold text-[56px] md:text-[68px] leading-[0.95] tracking-[-0.03em] max-w-[920px]">
          See your vulnerabilities<br/>
          <span className="text-[var(--ink-2)]">before</span> an attacker does.
        </h1>
        <p className="mt-6 max-w-[640px] text-[15px] leading-relaxed text-[var(--ink-1)]">
          Paste low-level code in C, C++, Rust, or Go. VulnCheck performs taint-aware static
          analysis to surface memory safety bugs, format string flaws, injection paths, and
          time-of-check races — with line-by-line explanations and remediation patterns built for learners.
        </p>
        <div className="mt-7 flex flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">
          {VULN_TYPES.map(v => (
            <span key={v} className="px-2.5 py-1 rounded-full border border-[var(--bd-1)] bg-[var(--bg-1)]">{v}</span>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/* Editor Panel                                                         */
/* ------------------------------------------------------------------ */

function EditorPanel({ code, setCode, language, setLanguage, onAnalyze, onFileUpload, scanning, error, isDirty }) {
  const taRef = useRef(null);
  const gutterRef = useRef(null);

  const lineCount = useMemo(() => Math.max(1, code.split('\n').length), [code]);
  const lines = useMemo(() => Array.from({length: lineCount}, (_, i) => i + 1), [lineCount]);

  // sync scroll between gutter and textarea
  const onScroll = () => {
    if (gutterRef.current && taRef.current) {
      gutterRef.current.scrollTop = taRef.current.scrollTop;
    }
  };

  const onKeyDown = (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const ta = taRef.current;
      const start = ta.selectionStart, end = ta.selectionEnd;
      const v = code;
      const next = v.substring(0, start) + '    ' + v.substring(end);
      setCode(next);
      requestAnimationFrame(() => { ta.selectionStart = ta.selectionEnd = start + 4; });
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
      e.preventDefault();
      onAnalyze();
    }
  };

  return (
    <div className="relative panel overflow-hidden">
      {/* corner crosshairs */}
      <span className="corner border-t border-l absolute top-2 left-2"></span>
      <span className="corner border-t border-r absolute top-2 right-2"></span>
      <span className="corner border-b border-l absolute bottom-2 left-2"></span>
      <span className="corner border-b border-r absolute bottom-2 right-2"></span>

      {/* Title bar */}
      <div className="flex items-center justify-between px-4 h-11 border-b border-[var(--bd-1)] bg-[rgba(7,10,20,0.5)]">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FF5577]/70"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-[#FFB547]/70"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--accent)]/70"></span>
          </div>
          <span className="font-mono text-[11px] text-[var(--ink-1)]">
            ~/lab/<span className="text-[var(--ink-0)]">handler.{language === 'python' ? 'py' : 'c'}</span>
          </span>
          <span className="px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider rounded bg-[var(--bg-3)] text-[var(--ink-1)] border border-[var(--bd-1)]">unsaved</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <select
              value={language}
              onChange={e => setLanguage(e.target.value)}
              className="lang-select font-mono text-[11px] uppercase tracking-wider bg-[var(--bg-2)] border border-[var(--bd-1)] hover:border-[var(--bd-2)] text-[var(--ink-0)] rounded-md pl-2.5 py-1 cursor-pointer focus:outline-none focus:border-[var(--accent)]/40"
            >
              {LANGUAGES.map(l => <option key={l.id} value={l.id}>{l.label}</option>)}
            </select>
          </div>
          <Tooltip text="Load sample vulnerable code">
            <button
              onClick={() => setCode(language === 'python' ? PYTHON_SAMPLE_CODE : SAMPLE_CODE)}
              className="font-mono text-[10px] uppercase tracking-wider px-2 py-1 rounded-md border border-[var(--bd-1)] text-[var(--ink-2)] hover:text-[var(--ink-0)] hover:border-[var(--bd-2)] flex items-center gap-1 transition-colors"
            >
              <I.reset className="w-3 h-3" /> sample
            </button>
          </Tooltip>
          {onFileUpload && <FileUploadButton onFile={onFileUpload} scanning={scanning} language={language} />}
        </div>
      </div>

      {/* Editor body */}
      <div className="editor-shell relative">
        {/* scanline overlay */}
        {scanning && (
          <div className="absolute inset-0 pointer-events-none overflow-hidden z-10">
            <div className="scanline-y absolute inset-x-0 h-24" style={{
              background: 'linear-gradient(180deg, transparent, rgba(124,255,205,0.18) 50%, transparent)',
              boxShadow: '0 0 40px rgba(124,255,205,0.35)',
            }}></div>
            <div className="absolute inset-0" style={{
              backgroundImage: 'repeating-linear-gradient(0deg, transparent 0 3px, rgba(124,255,205,0.025) 3px 4px)',
            }}></div>
          </div>
        )}

        <div className="flex" style={{height: 420}}>
          <div ref={gutterRef} className="font-mono text-[12.5px] editor-gutter shrink-0 w-12 py-4 pr-3 overflow-hidden">
            {lines.map(n => <div key={n} style={{lineHeight: 1.65}}>{String(n).padStart(2, '0')}</div>)}
          </div>
          <textarea
            ref={taRef}
            value={code}
            onChange={e => setCode(e.target.value)}
            onScroll={onScroll}
            onKeyDown={onKeyDown}
            spellCheck={false}
            disabled={scanning}
            placeholder={`// Paste your ${language === 'python' ? 'Python' : 'C'} source code here\n// or click "sample" to load an example`}
            className="editor-textarea font-mono text-[12.5px] flex-1 py-4 pr-4 outline-none resize-none"
            style={{color: '#DCE3F5'}}
          />
        </div>

        {/* Status footer */}
        <div className="flex items-center justify-between px-4 h-9 border-t border-[var(--bd-1)] bg-[rgba(7,10,20,0.5)] font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">
          <div className="flex items-center gap-4">
            <span>{lineCount} lines</span>
            <span>{code.length} chars</span>
            <span className="hidden sm:inline">utf-8</span>
            <span className="hidden md:inline">spaces · 4</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="hidden sm:inline">⌘ + ↵ to analyze</span>
            <span className={`inline-block w-1.5 h-1.5 rounded-full ${error ? 'bg-[var(--sev-high)]' : 'bg-[var(--accent)]'}`}></span>
          </div>
        </div>
      </div>

      {/* Analyze button area */}
      <div className="p-4 flex flex-wrap items-center gap-3 border-t border-[var(--bd-1)] bg-[rgba(11,16,32,0.4)]">
        <button
          onClick={onAnalyze}
          disabled={scanning || !code.trim()}
          className="scan-btn flex items-center gap-2.5 rounded-lg px-5 py-3 font-mono text-[12px] uppercase tracking-[0.18em] disabled:cursor-not-allowed transition-all"
          style={isDirty ? {
            borderColor: 'rgba(124,255,205,0.75)',
            boxShadow: '0 0 0 1px rgba(124,255,205,0.45), 0 0 28px -4px rgba(124,255,205,0.7), inset 0 1px 0 rgba(124,255,205,0.25)',
          } : {}}
        >
          {scanning ? (
            <>
              <svg viewBox="0 0 24 24" className="w-4 h-4 spin-slow" fill="none">
                <circle cx="12" cy="12" r="9" stroke="rgba(124,255,205,0.2)" strokeWidth="2"/>
                <path d="M21 12a9 9 0 00-9-9" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round"/>
              </svg>
              Scanning…
            </>
          ) : (
            <>
              <I.bolt className="w-4 h-4 text-[var(--accent)]" />
              Analyze code
              <span className="ml-1 font-mono text-[10px] opacity-70">↵</span>
            </>
          )}
        </button>


        {error && (
          <div className="ml-auto flex items-center gap-2 font-mono text-[11px] text-[var(--sev-high)]">
            <I.warn className="w-3.5 h-3.5" /> {error}
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Scanning Animation                                                   */
/* ------------------------------------------------------------------ */

function ScanningState() {
  const [idx, setIdx] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setIdx(i => (i + 1) % SCAN_MESSAGES.length), 380);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="panel p-6 relative overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-px overflow-hidden">
        <div className="absolute inset-0" style={{background: 'linear-gradient(90deg, transparent, var(--accent), transparent)'}}></div>
      </div>
      <div className="flex items-center gap-3 mb-5">
        <div className="relative w-9 h-9 grid place-items-center rounded-md border border-[var(--bd-1)] bg-[var(--bg-2)]">
          <svg viewBox="0 0 24 24" className="w-4 h-4 spin-slow text-[var(--accent)]" fill="none">
            <circle cx="12" cy="12" r="9" stroke="rgba(124,255,205,0.2)" strokeWidth="2"/>
            <path d="M21 12a9 9 0 00-9-9" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
          </svg>
        </div>
        <div>
          <div className="font-display text-[18px] font-semibold">Static analysis in progress</div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)] mt-1">running 6 detector passes</div>
        </div>
      </div>

      {/* progress bar */}
      <div className="relative h-1.5 rounded-full bg-[var(--bg-2)] overflow-hidden border border-[var(--bd-1)]">
        <div className="absolute inset-y-0 left-0 w-full flow-bg" style={{
          background: 'linear-gradient(90deg, transparent, rgba(124,255,205,0.6), transparent)',
          backgroundSize: '40% 100%',
          animation: 'shimmer 1.8s linear infinite',
        }}></div>
      </div>

      {/* log */}
      <div className="mt-5 font-mono text-[12px] leading-relaxed bg-[var(--bg-1)]/60 border border-[var(--bd-1)] rounded-lg p-4">
        {SCAN_MESSAGES.slice(0, idx + 1).map((m, i) => (
          <div key={i} className="flex items-start gap-2">
            <span className="text-[var(--ink-3)] mt-0.5">[{String(i+1).padStart(2,'0')}]</span>
            <span className={i === idx ? 'text-[var(--accent)]' : 'text-[var(--ink-1)]'}>
              {m}{i === idx ? <span className="blink ml-0.5">▍</span> : <span className="text-[var(--ink-3)]"> ✓</span>}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Severity Badge + Summary Bar                                         */
/* ------------------------------------------------------------------ */

function SeverityBadge({ sev, size = 'sm' }) {
  const s = SEVERITY[sev] || SEVERITY.LOW;
  const sizing = size === 'lg' ? 'text-[11px] px-2.5 py-1' : 'text-[10px] px-2 py-0.5';
  return (
    <span
      className={`font-mono uppercase tracking-[0.18em] inline-flex items-center gap-1.5 rounded-md border ${sizing}`}
      style={{ background: s.tint, borderColor: s.color + '55', color: s.text }}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.color, boxShadow: `0 0 8px ${s.color}` }}></span>
      {s.label}
    </span>
  );
}

function SevCountCard({ k, s, n }) {
  const animated = useCountUp(n);
  return (
    <div
      className="relative bg-[var(--bg-1)]/50 border border-[var(--bd-1)] rounded-lg p-3.5 overflow-hidden transition-shadow duration-500"
      style={n > 0 ? { boxShadow: `0 0 0 1px ${s.color}22, 0 8px 28px -12px ${s.color}40` } : {}}
    >
      <div className="absolute inset-x-0 top-0 h-px" style={{background: `linear-gradient(90deg, transparent, ${s.color}, transparent)`}}></div>
      <SeverityBadge sev={k} />
      <div className="mt-3 flex items-end justify-between gap-2">
        <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)] leading-tight whitespace-pre-line">
          {k === 'HIGH' ? 'exploit-\nclass' : k === 'MEDIUM' ? 'remediate\nsoon' : 'best-\npractice'}
        </div>
        <span
          className="font-display text-[36px] font-semibold leading-none shrink-0"
          style={{color: n > 0 ? s.color : 'var(--ink-3)', textShadow: n > 0 ? `0 0 20px ${s.color}66` : 'none'}}
        >{animated}</span>
      </div>
    </div>
  );
}

function SummaryBar({ findings }) {
  const counts = useMemo(() => {
    const c = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
    return c;
  }, [findings]);

  const total = findings.length;
  const score = Math.max(0, 100 - (counts.HIGH*22 + counts.MEDIUM*9 + counts.LOW*3));
  const scoreColor = score >= 80 ? 'var(--accent)' : score >= 50 ? 'var(--sev-med)' : 'var(--sev-high)';
  const animScore = useCountUp(score, 700);
  const arc = (animScore / 100) * 94.2;

  return (
    <div className="panel reveal p-5 flex flex-col md:flex-row md:items-stretch gap-5">
      {/* Score */}
      <div className="flex items-center gap-4 md:pr-6 md:border-r border-[var(--bd-1)]">
        <div className="relative w-16 h-16">
          <svg viewBox="0 0 36 36" className="w-16 h-16 -rotate-90">
            <circle cx="18" cy="18" r="15" fill="none" stroke="var(--bd-1)" strokeWidth="2.5"/>
            <circle cx="18" cy="18" r="15" fill="none" stroke={scoreColor} strokeWidth="2.5"
              strokeDasharray={`${arc} 94.2`} strokeLinecap="round"
              style={{ filter: `drop-shadow(0 0 6px ${scoreColor})`, transition: 'stroke 0.4s' }} />
          </svg>
          <div className="absolute inset-0 grid place-items-center font-display text-[20px] font-semibold" style={{color: scoreColor}}>{animScore}</div>
        </div>
        <div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">safety score</div>
          <div className="font-display text-[15px] font-medium mt-0.5">{total === 0 ? 'No findings' : `${total} finding${total === 1 ? '' : 's'} surfaced`}</div>
        </div>
      </div>

      {/* Severity counts */}
      <div className="flex-1 grid grid-cols-3 gap-3">
        {['HIGH','MEDIUM','LOW'].map(k => (
          <SevCountCard key={k} k={k} s={SEVERITY[k]} n={counts[k]} />
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Result Card                                                          */
/* ------------------------------------------------------------------ */

function FindingCard({ f, index }) {
  const sev = SEVERITY[f.severity] || SEVERITY.LOW;
  const [expanded, setExpanded] = useState(true);
  const [copied, setCopied] = useState(false);

  const copySnippet = () => {
    if (!f.snippet) return;
    navigator.clipboard.writeText(f.snippet).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  };

  return (
    <article
      className={`panel reveal ${sev.glow} relative overflow-hidden transition-all duration-300 hover:translate-y-[-1px]`}
      style={{ animationDelay: `${index * 80}ms` }}
    >
      {/* top hairline */}
      <div className={`absolute inset-x-0 top-0 h-px ${sev.hair}`}></div>

      {/* corners */}
      <span className="corner border-t border-l absolute top-2 left-2" style={{borderColor: sev.color + '55'}}></span>
      <span className="corner border-t border-r absolute top-2 right-2" style={{borderColor: sev.color + '55'}}></span>

      <div className="p-5 md:p-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <SeverityBadge sev={f.severity} />
              {f.cwe && (
                <span className="font-mono text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-[var(--bg-2)] border border-[var(--bd-1)] text-[var(--ink-1)]">
                  {f.cwe}
                </span>
              )}
              {typeof f.line === 'number' && (
                <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">
                  line {f.line}
                </span>
              )}
            </div>
            <h3 className="font-display font-semibold text-[20px] tracking-tight leading-tight">
              {f.type || 'Unknown vulnerability'}
            </h3>
          </div>
          <Tooltip text={expanded ? 'Collapse' : 'Expand'} side="left">
            <button
              onClick={() => setExpanded(e => !e)}
              className="shrink-0 w-7 h-7 grid place-items-center rounded-md border border-[var(--bd-1)] text-[var(--ink-2)] hover:text-[var(--ink-0)] hover:border-[var(--bd-2)] transition-colors"
              aria-label={expanded ? 'Collapse' : 'Expand'}
            >
              <svg viewBox="0 0 24 24" className={`w-3.5 h-3.5 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none">
                <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
          </Tooltip>
        </div>

        {/* Snippet */}
        {f.snippet && (
          <div className="mb-4 rounded-lg overflow-hidden border" style={{borderColor: sev.color + '33', background: 'rgba(6,9,17,0.65)'}}>
            <div className="flex items-center justify-between px-3 py-1.5 border-b" style={{borderColor: sev.color + '22'}}>
              <span className="font-mono text-[9px] uppercase tracking-wider text-[var(--ink-2)]">flagged · {f.cwe || 'snippet'}</span>
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-[9px] uppercase tracking-wider" style={{color: sev.text}}>▲ vulnerable</span>
                <Tooltip text={copied ? 'Copied!' : 'Copy snippet'} side="left">
                  <button onClick={copySnippet} className="text-[var(--ink-2)] hover:text-[var(--ink-0)] transition-colors">
                    {copied
                      ? <I.check className="w-3 h-3" style={{color: 'var(--accent)'}} />
                      : <I.copy className="w-3 h-3" />}
                  </button>
                </Tooltip>
              </div>
            </div>
            <pre className="font-mono text-[12.5px] leading-relaxed p-3.5 whitespace-pre-wrap overflow-x-auto" style={{color: '#DCE3F5'}}>
              <span style={{color: sev.color, textShadow: `0 0 12px ${sev.color}40`}}>{f.snippet}</span>
            </pre>
          </div>
        )}

        {expanded && (
          <div className="grid md:grid-cols-2 gap-4">
            {/* Explanation */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <I.bug className="w-3.5 h-3.5 text-[var(--ink-2)]" />
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--ink-2)]">why it&rsquo;s dangerous</span>
              </div>
              <p className="text-[13.5px] leading-relaxed text-[var(--ink-1)]">{f.explanation || '—'}</p>
            </div>
            {/* Fix */}
            <div className="md:border-l md:pl-4 border-[var(--bd-1)]">
              <div className="flex items-center gap-2 mb-2">
                <I.fix className="w-3.5 h-3.5" style={{color: 'var(--accent)'}} />
                <span className="font-mono text-[10px] uppercase tracking-[0.18em]" style={{color: 'var(--accent)'}}>suggested fix</span>
              </div>
              <p className="text-[13.5px] leading-relaxed text-[var(--ink-1)] whitespace-pre-wrap">{f.fix || '—'}</p>
            </div>
          </div>
        )}
      </div>
    </article>
  );
}

/* ------------------------------------------------------------------ */
/* Empty / Clean states                                                 */
/* ------------------------------------------------------------------ */

function EmptyState() {
  return (
    <div className="panel p-8 text-center">
      <div className="mx-auto w-12 h-12 grid place-items-center rounded-full bg-[var(--bg-2)] border border-[var(--bd-1)] mb-4">
        <I.shield className="w-5 h-5 text-[var(--ink-2)]" />
      </div>
      <h3 className="font-display font-semibold text-[18px] mb-1.5">Ready when you are</h3>
      <p className="text-[13px] text-[var(--ink-1)] max-w-md mx-auto leading-relaxed">
        Drop code into the editor and press <span className="font-mono text-[var(--ink-0)]">Analyze</span>.
        Findings stream in as the engine completes each detector pass.
      </p>
      <div className="mt-5 inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">
        <span className="w-1 h-1 rounded-full bg-[var(--ink-2)]"></span>
        awaiting input
      </div>
    </div>
  );
}

function CleanState() {
  return (
    <div className="panel glow-accent reveal p-8 text-center relative overflow-hidden">
      <div className="absolute inset-x-0 top-0 h-px" style={{background: 'linear-gradient(90deg, transparent, var(--accent), transparent)'}}></div>
      <div className="mx-auto w-14 h-14 grid place-items-center rounded-full border mb-4"
        style={{borderColor: 'rgba(124,255,205,0.4)', background: 'rgba(124,255,205,0.08)', boxShadow: '0 0 30px -6px rgba(124,255,205,0.5)'}}>
        <I.check className="w-7 h-7" style={{color: 'var(--accent)'}} />
      </div>
      <h3 className="font-display font-semibold text-[22px] tracking-tight">No vulnerabilities detected</h3>
      <p className="text-[13px] text-[var(--ink-1)] mt-2 max-w-md mx-auto leading-relaxed">
        Across all six detector passes, no instances of the configured vulnerability classes were found.
      </p>
      <p className="text-[11px] text-[var(--ink-2)] mt-3 font-mono">
        static analysis isn&rsquo;t exhaustive — pair with fuzzing &amp; review.
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Backend wiring — local C analysis engine via /analyze               */
/* ------------------------------------------------------------------ */

function normalizeFindings(data) {
  if (!data || !Array.isArray(data.findings)) return [];
  const SEV = new Set(['HIGH','MEDIUM','LOW']);
  return data.findings.map(f => ({
    type: f.type || 'Unknown',
    severity: SEV.has((f.severity || '').toUpperCase()) ? f.severity.toUpperCase() : 'LOW',
    line: Number.isFinite(f.line) ? f.line : (parseInt(f.line, 10) || null),
    snippet: typeof f.snippet === 'string' ? f.snippet : '',
    explanation: typeof f.explanation === 'string' ? f.explanation : '',
    fix: typeof f.fix === 'string' ? f.fix : '',
    cwe: typeof f.cwe === 'string' ? f.cwe : '',
  }));
}

/* Send code text to /analyze */
async function analyzeCode(code, language) {
  const res = await fetch('/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, language: language || 'c' }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Server error ${res.status}`);
  }
  return res.json();
}

/* Send a .c file to /analyze/upload */
async function analyzeFile(file) {
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch('/analyze/upload', { method: 'POST', body: fd });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Server error ${res.status}`);
  }
  return res.json();
}

/* ------------------------------------------------------------------ */
/* File Upload Button component                                         */
/* ------------------------------------------------------------------ */

function FileUploadButton({ onFile, scanning, language }) {
  const inputRef = useRef(null);
  const ext = language === 'python' ? '.py' : '.c';

  const handleChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    onFile(file);
    e.target.value = '';
  };

  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept=".c,.py,text/plain"
        style={{ display: 'none' }}
        onChange={handleChange}
      />
      <Tooltip text={`Upload a ${ext} source file`}>
        <button
          onClick={() => inputRef.current && inputRef.current.click()}
          disabled={scanning}
          className="font-mono text-[10px] uppercase tracking-wider px-2 py-1 rounded-md border border-[var(--bd-1)] text-[var(--ink-2)] hover:text-[var(--ink-0)] hover:border-[var(--bd-2)] flex items-center gap-1 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <svg viewBox="0 0 24 24" className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
          </svg>
          upload {ext}
        </button>
      </Tooltip>
    </>
  );
}

/* ------------------------------------------------------------------ */
/* Root                                                                 */
/* ------------------------------------------------------------------ */

function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('c');
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState(null);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [uploadedName, setUploadedName] = useState(null);
  const [fromCache, setFromCache] = useState(false);
  const [lastScannedCode, setLastScannedCode] = useState('');
  const resultCache = useRef(new Map());
  const tStart = useRef(0);

  const isDirty = findings !== null && code.trim() !== lastScannedCode;

  // elapsed timer
  useEffect(() => {
    if (!scanning) return;
    tStart.current = performance.now();
    setElapsed(0);
    const t = setInterval(() => setElapsed((performance.now() - tStart.current) / 1000), 80);
    return () => clearInterval(t);
  }, [scanning]);

  // Analyze pasted / typed code
  const runAnalysis = useCallback(async () => {
    if (!code.trim() || scanning) return;
    const key = `${language}:${code.trim()}`;

    // Serve from cache instantly — no network call
    if (resultCache.current.has(key)) {
      setFromCache(true);
      setError(null);
      setFindings(resultCache.current.get(key));
      setLastScannedCode(code.trim());
      return;
    }

    setFromCache(false);
    setError(null);
    setScanning(true);
    setFindings(null);
    setUploadedName(null);
    try {
      const [data] = await Promise.all([
        analyzeCode(code, language),
        new Promise(r => setTimeout(r, 900)),
      ]);
      if (data.error && (!data.findings || data.findings.length === 0)) {
        setError(data.error);
        setFindings([]);
      } else {
        const normalized = normalizeFindings(data);
        resultCache.current.set(key, normalized);
        setFindings(normalized);
      }
      setLastScannedCode(code.trim());
    } catch (e) {
      console.error(e);
      setError(e.message || 'analyzer unavailable — please retry');
      setFindings([]);
    } finally {
      setScanning(false);
    }
  }, [code, language, scanning]);

  // Analyze uploaded file
  const runFileAnalysis = useCallback(async (file) => {
    if (scanning) return;
    setFromCache(false);
    setError(null);
    setScanning(true);
    setFindings(null);
    setUploadedName(file.name);
    try {
      const text = await file.text();
      setCode(text);
      const [data] = await Promise.all([
        analyzeFile(file),
        new Promise(r => setTimeout(r, 900)),
      ]);
      if (data.error && (!data.findings || data.findings.length === 0)) {
        setError(data.error);
        setFindings([]);
      } else {
        const normalized = normalizeFindings(data);
        resultCache.current.set(text.trim(), normalized);
        setFindings(normalized);
      }
      setLastScannedCode(text.trim());
    } catch (e) {
      console.error(e);
      setError(e.message || 'file upload failed — please retry');
      setFindings([]);
    } finally {
      setScanning(false);
    }
  }, [scanning]);

  return (
    <div className="min-h-screen relative">
      <Background />
      <Header activeTab={activeTab} setActiveTab={setActiveTab} />

      {activeTab !== 'scanner' && (
        <div key={activeTab} className="reveal" style={{ animationDuration: '0.3s' }}>
          {activeTab === 'cwe catalog' && <CweCatalogSection />}
          {activeTab === 'lessons' && <LessonsSection />}
          {activeTab === 'docs' && <DocsSection />}
        </div>
      )}

      {activeTab === 'scanner' && <Hero />}
      {activeTab === 'scanner' && <main className="relative z-10 max-w-[1400px] mx-auto px-6 pb-24">
        <div className="grid lg:grid-cols-[1.15fr_1fr] gap-6 items-start">
          {/* Left: editor */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-1 h-4 bg-[var(--accent)]" style={{boxShadow: '0 0 12px var(--accent)'}}></span>
                <h2 className="font-display font-semibold text-[15px] tracking-tight uppercase">Source</h2>
                <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">— paste · edit · upload</span>
              </div>
              <div className="flex items-center gap-3">
                {uploadedName && (
                  <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--accent)] flex items-center gap-1">
                    <svg viewBox="0 0 24 24" className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
                    {uploadedName}
                  </span>
                )}
                <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">
                  {language.toUpperCase()} · {code.split('\n').length} ln
                </span>
              </div>
            </div>
            <EditorPanel
              code={code} setCode={setCode}
              language={language} setLanguage={setLanguage}
              onAnalyze={runAnalysis}
              onFileUpload={runFileAnalysis}
              scanning={scanning}
              error={error}
              isDirty={isDirty}
            />

            {/* Helper strip */}
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)] px-1">
              <span className="flex items-center gap-1.5"><span className="w-1 h-1 rounded-full bg-[var(--accent)]"></span> taint-aware</span>
              <span className="flex items-center gap-1.5"><span className="w-1 h-1 rounded-full bg-[var(--accent)]"></span> CWE-mapped</span>
              <span className="flex items-center gap-1.5"><span className="w-1 h-1 rounded-full bg-[var(--accent)]"></span> teach-by-example</span>
            </div>
          </div>

          {/* Right: results */}
          <div className="space-y-4 lg:sticky lg:top-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-1 h-4 bg-[var(--azure)]" style={{boxShadow: '0 0 12px var(--azure)'}}></span>
                <h2 className="font-display font-semibold text-[15px] tracking-tight uppercase">Findings</h2>
                <span className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">— results</span>
              </div>
              <div className="font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">
                {scanning ? (
                  <span className="flex items-center gap-1.5">
                    <svg viewBox="0 0 24 24" className="w-3 h-3 spin-slow text-[var(--accent)]" fill="none">
                      <circle cx="12" cy="12" r="9" stroke="rgba(124,255,205,0.2)" strokeWidth="2"/>
                      <path d="M21 12a9 9 0 00-9-9" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                    {elapsed.toFixed(1)}s
                  </span>
                ) : findings === null ? 'idle' : (
                  <span className="flex items-center gap-2">
                    <span>{findings.length} reported</span>
                    {fromCache && (
                      <Tooltip text="Served from cache — no API call made">
                        <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-[var(--accent)]/10 border border-[var(--accent)]/30 text-[var(--accent)] cursor-default">
                          <svg viewBox="0 0 24 24" className="w-2.5 h-2.5" fill="none">
                            <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
                          </svg>
                          cached
                        </span>
                      </Tooltip>
                    )}
                  </span>
                )}
              </div>
            </div>

            {/* Optimistic: show skeletons immediately while scanning */}
            {scanning && (
              <div className="panel reveal p-5">
                <SkeletonDemo />
              </div>
            )}

            {!scanning && findings === null && <EmptyState />}

            {!scanning && findings !== null && findings.length === 0 && !error && <CleanState />}

            {!scanning && findings !== null && findings.length > 0 && (
              <>
                <SummaryBar findings={findings} />
                <div className="space-y-4">
                  {findings.map((f, i) => <FindingCard key={i} f={f} index={i} />)}
                </div>
              </>
            )}

            {!scanning && error && findings !== null && findings.length === 0 && (
              <div className="panel p-5 reveal">
                <div className="flex items-start gap-3">
                  <I.warn className="w-5 h-5 text-[var(--sev-high)] shrink-0 mt-0.5" />
                  <div>
                    <div className="font-display font-semibold text-[15px]">Analyzer returned an unexpected response</div>
                    <div className="text-[13px] text-[var(--ink-1)] mt-1 leading-relaxed">{error}. Try simplifying the snippet or re-running.</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>}

      <footer className="relative z-10 border-t border-[var(--bd-1)] bg-[rgba(11,16,32,0.5)] backdrop-blur-xl">
        <div className="max-w-[1400px] mx-auto px-6 py-5 flex flex-wrap items-center justify-between gap-3 font-mono text-[10px] uppercase tracking-wider text-[var(--ink-2)]">
          <div className="flex items-center gap-3">
            <Logo />
          </div>
          <div className="flex items-center gap-4">
            <span>© 2026 vulncheck labs</span>
            <span>·</span>
            <span>built for cs · 4720</span>
            <span>·</span>
            <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] pulse-dot"></span> service ok</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
