/**
 * VulnCheck API Server
 * Serves the frontend and wraps the C and Python analysis engines.
 */

const express  = require('express');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const os       = require('os');
const { spawn } = require('child_process');

const app       = express();
const PORT      = process.env.PORT || 3000;
const ENGINE_C  = path.join(__dirname, 'vulncheck');
const ENGINE_PY = path.join(__dirname, 'vulncheck_python.py');
/* Dynamically find whatever Python 3 binary is available */
const { execSync } = require('child_process');
function findPython() {
  const candidates = process.platform === 'win32'
    ? ['python', 'python3', 'py']
    : ['python3', 'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3.9', 'python'];
  for (const cmd of candidates) {
    try { execSync(`${cmd} --version`, { stdio: 'ignore' }); return cmd; }
    catch (_) {}
  }
  return null;
}
const PYTHON = findPython();
console.log(PYTHON ? `[python] found: ${PYTHON}` : '[python] WARNING: no Python interpreter found — Python analysis disabled');

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ok = file.originalname.endsWith('.c') ||
               file.originalname.endsWith('.py') ||
               file.mimetype === 'text/plain'    ||
               file.mimetype === 'application/octet-stream';
    cb(ok ? null : new Error('Only .c or .py source files are accepted'), ok);
  },
});

/* Static assets */
app.use(express.static(__dirname));

/* Root route */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'VulnCheck.html'));
});

function runEngine(code) {
  return new Promise((resolve, reject) => {
    const tmp = path.join(os.tmpdir(), `vc_${Date.now()}_${Math.random().toString(36).slice(2)}.c`);
    fs.writeFileSync(tmp, code, 'utf8');

    let stdout = '';
    let stderr = '';
    const proc = spawn(ENGINE_C, [tmp], { timeout: 15000 });

    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.stderr.on('data', d => { stderr += d.toString(); });

    proc.on('close', (code) => {
      fs.unlink(tmp, () => {});
      if (code !== 0 && !stdout.trim()) {
        return reject(new Error(`Engine exited ${code}: ${stderr}`));
      }
      try {
        const data = JSON.parse(stdout);
        resolve(data);
      } catch (e) {
        reject(new Error(`Engine output not valid JSON: ${stdout.slice(0, 200)}`));
      }
    });

    proc.on('error', (err) => {
      fs.unlink(tmp, () => {});
      reject(err);
    });
  });
}

function runPythonEngine(code) {
  if (!PYTHON) {
    return Promise.reject(new Error('No Python 3 interpreter found on this server. Install Python 3 to enable Python analysis.'));
  }
  return new Promise((resolve, reject) => {
    const tmp = path.join(os.tmpdir(), `vc_${Date.now()}_${Math.random().toString(36).slice(2)}.py`);
    fs.writeFileSync(tmp, code, 'utf8');

    let stdout = '';
    let stderr = '';
    const proc = spawn(PYTHON, [ENGINE_PY, tmp], { timeout: 15000 });

    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.stderr.on('data', d => { stderr += d.toString(); });

    proc.on('close', (code) => {
      fs.unlink(tmp, () => {});
      if (code !== 0 && !stdout.trim()) {
        return reject(new Error(`Python engine exited ${code}: ${stderr}`));
      }
      try {
        const data = JSON.parse(stdout);
        resolve(data);
      } catch (e) {
        reject(new Error(`Python engine output not valid JSON: ${stdout.slice(0, 200)}`));
      }
    });

    proc.on('error', (err) => {
      fs.unlink(tmp, () => {});
      if (err.code === 'ENOENT') {
        reject(new Error(`Python interpreter (${PYTHON}) not found on this server. Install Python 3 to enable Python analysis.`));
      } else {
        reject(err);
      }
    });
  });
}

app.post('/analyze', async (req, res) => {
  const { code, language } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Missing code field', findings: [] });
  }
  if (language && language !== 'c' && language !== 'python') {
    return res.status(400).json({
      error: 'Only C and Python are supported.',
      findings: [],
    });
  }
  try {
    const result = language === 'python'
      ? await runPythonEngine(code)
      : await runEngine(code);
    res.json(result);
  } catch (err) {
    console.error('[analyze]', err.message);
    res.status(500).json({ error: err.message, findings: [] });
  }
});

app.post('/analyze/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded', findings: [] });
  }
  const code = req.file.buffer.toString('utf8');
  const isPython = req.file.originalname.endsWith('.py');
  try {
    const result = isPython ? await runPythonEngine(code) : await runEngine(code);
    res.json(result);
  } catch (err) {
    console.error('[upload]', err.message);
    res.status(500).json({ error: err.message, findings: [] });
  }
});

app.get('/health', (req, res) => {
  const cEngineExists  = fs.existsSync(ENGINE_C);
  const pyEngineExists = fs.existsSync(ENGINE_PY);
  res.json({
    status: 'ok',
    engine_c:      cEngineExists  ? 'ready' : 'missing — run make',
    engine_python: pyEngineExists ? 'ready' : 'missing',
    port: PORT,
  });
});

app.listen(PORT, () => {
  console.log(`\n  VulnCheck server running at http://localhost:${PORT}`);
  console.log(`  C engine     : ${ENGINE_C}`);
  console.log(`  Python engine: ${ENGINE_PY}`);
  console.log(`  Health check : http://localhost:${PORT}/health\n`);
});
