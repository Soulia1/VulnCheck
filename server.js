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
const { analyzePython } = require('./vulncheck_python');

const app      = express();
const PORT     = process.env.PORT || 3000;
const ENGINE_C = path.join(__dirname, 'vulncheck');

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
  try {
    return Promise.resolve(analyzePython(code));
  } catch (err) {
    return Promise.reject(err);
  }
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
  const cEngineExists = fs.existsSync(ENGINE_C);
  res.json({
    status: 'ok',
    engine_c:      cEngineExists ? 'ready' : 'missing — run make',
    engine_python: 'ready (Node.js)',
    port: PORT,
  });
});

app.listen(PORT, () => {
  console.log(`\n  VulnCheck server running at http://localhost:${PORT}`);
  console.log(`  C engine     : ${ENGINE_C}`);
  console.log(`  Python engine: Node.js (vulncheck_python.js)`);
  console.log(`  Health check : http://localhost:${PORT}/health\n`);
});
