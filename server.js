/**
 * VulnCheck API Server
 * Serves the frontend and wraps the C analysis engine.
 */

const express  = require('express');
const multer   = require('multer');
const path     = require('path');
const fs       = require('fs');
const os       = require('os');
const { spawn } = require('child_process');

const app    = express();
const PORT   = process.env.PORT || 3000;
const ENGINE = path.join(__dirname, 'vulncheck');

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ok = file.originalname.endsWith('.c') ||
               file.mimetype === 'text/plain'   ||
               file.mimetype === 'application/octet-stream';
    cb(ok ? null : new Error('Only .c source files are accepted'), ok);
  },
});

/* Static assets (images, jsx etc) */
app.use(express.static(__dirname));

/* Root route — serve VulnCheck.html */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'VulnCheck.html'));
});

function runEngine(code) {
  return new Promise((resolve, reject) => {
    const tmp = path.join(os.tmpdir(), `vc_${Date.now()}_${Math.random().toString(36).slice(2)}.c`);
    fs.writeFileSync(tmp, code, 'utf8');

    let stdout = '';
    let stderr = '';
    const proc = spawn(ENGINE, [tmp], { timeout: 15000 });

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

app.post('/analyze', async (req, res) => {
  const { code, language } = req.body;
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Missing code field', findings: [] });
  }
  if (language && language !== 'c') {
    return res.status(400).json({
      error: 'This backend only supports C. Select C in the editor.',
      findings: [],
    });
  }
  try {
    const result = await runEngine(code);
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
  try {
    const result = await runEngine(code);
    res.json(result);
  } catch (err) {
    console.error('[upload]', err.message);
    res.status(500).json({ error: err.message, findings: [] });
  }
});

app.get('/health', (req, res) => {
  const engineExists = fs.existsSync(ENGINE);
  res.json({
    status: 'ok',
    engine: engineExists ? 'ready' : 'missing — run make',
    port: PORT,
  });
});

app.listen(PORT, () => {
  console.log(`\n  VulnCheck server running at http://localhost:${PORT}`);
  console.log(`  Engine binary : ${ENGINE}`);
  console.log(`  Health check  : http://localhost:${PORT}/health\n`);
});
