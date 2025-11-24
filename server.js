require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const Database = require('better-sqlite3');
const { Readable } = require('stream');

const app = express();
const port = process.env.PORT || 3000;
const jwtSecret = process.env.JWT_SECRET || 'dev-secret';
const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'app.db');
const storageRoot = path.resolve(process.env.STORAGE_ROOT || path.join(__dirname, 'storage', 'documents'));
const logFile = path.join(__dirname, 'logs', 'app.log');

fs.mkdirSync(path.dirname(dbPath), { recursive: true });
fs.mkdirSync(storageRoot, { recursive: true });
fs.mkdirSync(path.dirname(logFile), { recursive: true });

const db = new Database(dbPath);
db.pragma('foreign_keys = ON');

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, storageRoot),
    filename: (_req, file, cb) => {
      const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
      cb(null, `${unique}${path.extname(file.originalname)}`);
    },
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
});

const makeStoredName = (original) => {
  const ext = path.extname(original || '') || '';
  const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  return `${unique}${ext}`;
};

const extractNameFromUrl = (url) => {
  try {
    const parsed = new URL(url);
    const base = path.basename(parsed.pathname);
    return base ? decodeURIComponent(base) : 'download.bin';
  } catch (_e) {
    return 'download.bin';
  }
};

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const sendError = (res, error, message, status = 400) => res.status(status).json({ error, message });

const paginate = (req) => {
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const pageSizeRaw = parseInt(req.query.page_size, 10) || 20;
  const page_size = Math.min(Math.max(pageSizeRaw, 1), 100);
  const offset = (page - 1) * page_size;
  return { page, page_size, offset };
};

const parseArray = (value) => {
  if (!value) return [];
  if (Array.isArray(value)) return value.filter((v) => v !== '');
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch (_e) {
      return value.split(',').map((v) => v.trim()).filter(Boolean);
    }
  }
  return [];
};

const logLine = (type, message, meta = {}) => {
  const entry = { ts: new Date().toISOString(), type, message, ...meta };
  fs.appendFileSync(logFile, `${JSON.stringify(entry)}\n`);
};

const logAdminAction = (username, action, meta = {}) => logLine('audit', action, { username, ...meta });

const runMigrations = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS stands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      status TEXT DEFAULT 'draft',
      owner TEXT DEFAULT '',
      tags TEXT DEFAULT '[]',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stand_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      file_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT DEFAULT 'application/octet-stream',
      editable_inline INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      created_by TEXT DEFAULT '',
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stand_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      inventory_number TEXT,
      location TEXT,
      cpu TEXT,
      ram TEXT,
      storage TEXT,
      network TEXT,
      role TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS distribution_products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stand_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS distribution_versions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      file_name TEXT NOT NULL,
      file_path TEXT NOT NULL,
      description TEXT DEFAULT '',
      is_active INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (product_id) REFERENCES distribution_products(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS vm_groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stand_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS vms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stand_id INTEGER NOT NULL,
      group_id INTEGER,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      ips TEXT DEFAULT '[]',
      os TEXT DEFAULT '',
      role TEXT DEFAULT '',
      ssh_port INTEGER DEFAULT 22,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE,
      FOREIGN KEY (group_id) REFERENCES vm_groups(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS graph_nodes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stand_id INTEGER NOT NULL,
      vm_id INTEGER NOT NULL,
      x REAL NOT NULL,
      y REAL NOT NULL,
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE,
      FOREIGN KEY (vm_id) REFERENCES vms(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS graph_edges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      stand_id INTEGER NOT NULL,
      source_node_id INTEGER NOT NULL,
      target_node_id INTEGER NOT NULL,
      description TEXT DEFAULT '',
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE,
      FOREIGN KEY (source_node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
      FOREIGN KEY (target_node_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS download_jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL, -- document | distribution_version
      stand_id INTEGER,
      product_id INTEGER,
      title TEXT,
      description TEXT,
      editable_inline INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 0,
      url TEXT NOT NULL,
      status TEXT DEFAULT 'queued',
      progress_bytes INTEGER DEFAULT 0,
      total_bytes INTEGER,
      stored_name TEXT,
      file_name TEXT,
      mime_type TEXT,
      error TEXT,
      created_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (stand_id) REFERENCES stands(id) ON DELETE CASCADE,
      FOREIGN KEY (product_id) REFERENCES distribution_products(id) ON DELETE CASCADE
    );
  `);
};

const seedAdmin = () => {
  const adminCount = db.prepare('SELECT COUNT(*) as c FROM admins').get().c;
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || 'admin';
  if (adminCount === 0) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(username, hash);
    logLine('info', 'Created default admin account', { username });
  }
};

runMigrations();
seedAdmin();

const issueToken = (username) => jwt.sign({ username, role: 'admin' }, jwtSecret, { expiresIn: '8h' });

const requireAdmin = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return sendError(res, 'unauthorized', 'Authorization required', 401);
  try {
    const payload = jwt.verify(token, jwtSecret);
    req.user = { username: payload.username };
    return next();
  } catch (_e) {
    return sendError(res, 'unauthorized', 'Invalid or expired token', 401);
  }
};

const buildListResponse = (items, total, page, page_size) => ({ items, page, page_size, total });

// ---- Download worker (persistent queue) ----
const abortControllers = new Map(); // jobId -> { controller, filePath }

const markStaleRunningAsQueued = () => {
  db.prepare("UPDATE download_jobs SET status = 'queued', updated_at = ? WHERE status = 'running'").run(new Date().toISOString());
};

const getNextJob = () => db.prepare("SELECT * FROM download_jobs WHERE status IN ('queued','running') ORDER BY created_at LIMIT 1").get();

const updateJob = (id, data) => {
  const fields = Object.keys(data);
  const placeholders = fields.map((f) => `${f} = ?`).join(', ');
  const values = fields.map((f) => data[f]);
  db.prepare(`UPDATE download_jobs SET ${placeholders} WHERE id = ?`).run(...values, id);
};

const createDocumentFromJob = (job) => {
  const now = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO documents (stand_id, title, description, file_name, stored_name, mime_type, editable_inline, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(
    job.stand_id,
    job.title || job.file_name,
    job.description || '',
    job.file_name,
    job.stored_name,
    job.mime_type || 'application/octet-stream',
    job.editable_inline ? 1 : 0,
    now,
    job.created_by || '',
  );
  return db.prepare('SELECT * FROM documents WHERE id = ?').get(result.lastInsertRowid);
};

const createDistributionVersionFromJob = (job) => {
  const now = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO distribution_versions (product_id, file_name, file_path, description, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(job.product_id, job.file_name, job.stored_name, job.description || '', job.is_active ? 1 : 0, now);
  const created = db.prepare('SELECT * FROM distribution_versions WHERE id = ?').get(result.lastInsertRowid);
  if (job.is_active) {
    db.prepare('UPDATE distribution_versions SET is_active = 0 WHERE product_id = ? AND id != ?').run(job.product_id, created.id);
  }
  return created;
};

const downloadAndStore = async (job) => {
  const controller = new AbortController();
  abortControllers.set(job.id, { controller });
  const now = new Date().toISOString();
  updateJob(job.id, { status: 'running', updated_at: now });

  const response = await fetch(job.url, { signal: controller.signal });
  if (!response.ok) throw new Error(`Remote responded with ${response.status}`);
  const total = Number(response.headers.get('content-length')) || null;
  if (total) updateJob(job.id, { total_bytes: total, updated_at: new Date().toISOString() });

  const originalName = job.file_name || extractNameFromUrl(job.url);
  const storedName = makeStoredName(originalName);
  const destPath = path.join(storageRoot, storedName);
  abortControllers.get(job.id).filePath = destPath;

  const nodeStream = Readable.fromWeb(response.body);
  const fileStream = fs.createWriteStream(destPath);
  let downloaded = 0;

  await new Promise((resolve, reject) => {
    nodeStream.on('data', (chunk) => {
      downloaded += chunk.length;
      updateJob(job.id, { progress_bytes: downloaded, updated_at: new Date().toISOString() });
    });
    nodeStream.on('error', reject);
    fileStream.on('error', reject);
    fileStream.on('finish', resolve);
    nodeStream.pipe(fileStream);
  });

  const mime = response.headers.get('content-type') || 'application/octet-stream';
  updateJob(job.id, {
    status: 'completed',
    stored_name: storedName,
    file_name: originalName,
    mime_type: mime,
    updated_at: new Date().toISOString(),
  });

  let createdRecord = null;
  if (job.kind === 'document') {
    createdRecord = createDocumentFromJob({
      ...job,
      stored_name: storedName,
      file_name: originalName,
      mime_type: mime,
    });
  } else if (job.kind === 'distribution_version') {
    createdRecord = createDistributionVersionFromJob({
      ...job,
      stored_name: storedName,
      file_name: originalName,
      mime_type: mime,
    });
  }
  abortControllers.delete(job.id);
  return createdRecord;
};

let workerActive = false;
const processQueue = async () => {
  if (workerActive) return;
  workerActive = true;
  try {
    while (true) {
      const job = getNextJob();
      if (!job) break;
      if (job.status === 'queued') updateJob(job.id, { status: 'running', updated_at: new Date().toISOString() });
      try {
        await downloadAndStore(job);
      } catch (err) {
        const current = db.prepare('SELECT status FROM download_jobs WHERE id = ?').get(job.id);
        if (current && current.status === 'cancelled') {
          // Already cancelled; clean up.
        } else {
          const meta = { status: 'failed', error: err.message, updated_at: new Date().toISOString() };
          updateJob(job.id, meta);
        }
        const entry = abortControllers.get(job.id);
        if (entry && entry.filePath && fs.existsSync(entry.filePath)) fs.unlinkSync(entry.filePath);
        abortControllers.delete(job.id);
      }
    }
  } finally {
    workerActive = false;
  }
};

const cancelJob = (jobId) => {
  const running = abortControllers.get(jobId);
  if (running) {
    running.controller.abort();
    if (running.filePath && fs.existsSync(running.filePath)) fs.unlinkSync(running.filePath);
  }
  updateJob(jobId, { status: 'cancelled', updated_at: new Date().toISOString() });
};

markStaleRunningAsQueued();
processQueue();

// Auth
app.post('/api/v1/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return sendError(res, 'invalid_request', 'Username and password are required', 400);
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  if (!admin) return sendError(res, 'invalid_credentials', 'Invalid username or password', 401);
  const ok = bcrypt.compareSync(password, admin.password_hash);
  if (!ok) return sendError(res, 'invalid_credentials', 'Invalid username or password', 401);
  const token = issueToken(username);
  return res.json({ token });
});

app.post('/api/v1/auth/logout', requireAdmin, (req, res) => res.json({ success: true }));

// Stands
app.get('/api/v1/stands', (req, res) => {
  const { q, status, tag } = req.query;
  const { page, page_size, offset } = paginate(req);
  const conditions = [];
  const params = [];
  if (q) {
    conditions.push('(name LIKE ? OR description LIKE ?)');
    params.push(`%${q}%`, `%${q}%`);
  }
  if (status) {
    conditions.push('status = ?');
    params.push(status);
  }
  if (tag) {
    conditions.push("tags LIKE ?");
    params.push(`%${tag}%`);
  }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const items = db.prepare(`SELECT * FROM stands ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, page_size, offset)
    .map((s) => ({ ...s, tags: parseArray(s.tags) }));
  const total = db.prepare(`SELECT COUNT(*) as c FROM stands ${where}`).get(...params).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.get('/api/v1/stands/:id', (req, res) => {
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(req.params.id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  res.json({ ...stand, tags: parseArray(stand.tags) });
});

app.post('/api/v1/stands', requireAdmin, (req, res) => {
  const { name, description = '', status = 'draft', owner = '', tags = [] } = req.body || {};
  if (!name) return sendError(res, 'invalid_request', 'Name is required');
  const now = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO stands (name, description, status, owner, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(name, description, status, owner, JSON.stringify(parseArray(tags)), now, now);
  const created = db.prepare('SELECT * FROM stands WHERE id = ?').get(result.lastInsertRowid);
  logAdminAction(req.user.username, 'create_stand', { stand_id: created.id });
  res.status(201).json({ ...created, tags: parseArray(created.tags) });
});

app.put('/api/v1/stands/:id', requireAdmin, (req, res) => {
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(req.params.id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  const { name = stand.name, description = stand.description, status = stand.status, owner = stand.owner, tags = parseArray(stand.tags) } = req.body || {};
  const now = new Date().toISOString();
  db.prepare(
    'UPDATE stands SET name = ?, description = ?, status = ?, owner = ?, tags = ?, updated_at = ? WHERE id = ?',
  ).run(name, description, status, owner, JSON.stringify(parseArray(tags)), now, stand.id);
  const updated = db.prepare('SELECT * FROM stands WHERE id = ?').get(stand.id);
  logAdminAction(req.user.username, 'update_stand', { stand_id: stand.id });
  res.json({ ...updated, tags: parseArray(updated.tags) });
});

app.delete('/api/v1/stands/:id', requireAdmin, (req, res) => {
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(req.params.id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  db.prepare('DELETE FROM stands WHERE id = ?').run(stand.id);
  logAdminAction(req.user.username, 'delete_stand', { stand_id: stand.id });
  res.json({ success: true });
});

// Documents
app.get('/api/v1/stands/:stand_id/documents', (req, res) => {
  const { stand_id } = req.params;
  const { q } = req.query;
  const { page, page_size, offset } = paginate(req);
  const conditions = ['stand_id = ?'];
  const params = [stand_id];
  if (q) {
    conditions.push('title LIKE ?');
    params.push(`%${q}%`);
  }
  const where = `WHERE ${conditions.join(' AND ')}`;
  const items = db.prepare(`SELECT * FROM documents ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, page_size, offset);
  const total = db.prepare(`SELECT COUNT(*) as c FROM documents ${where}`).get(...params).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.post('/api/v1/stands/:stand_id/documents', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const { stand_id } = req.params;
    const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(stand_id);
    if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
    const file = req.file;
    const url = req.body?.url;
    const { title, description = '', editable_inline = false, created_by = req.user.username || '' } = req.body || {};
    const isInline = editable_inline === 'true' || editable_inline === true || editable_inline === '1';

    if (file) {
      const storedName = file.filename;
      const fileName = file.originalname;
      const result = db.prepare(
        'INSERT INTO documents (stand_id, title, description, file_name, stored_name, mime_type, editable_inline, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ).run(
        stand_id,
        title || fileName,
        description,
        fileName,
        storedName,
        file.mimetype,
        isInline ? 1 : 0,
        new Date().toISOString(),
        created_by,
      );
      const created = db.prepare('SELECT * FROM documents WHERE id = ?').get(result.lastInsertRowid);
      logAdminAction(req.user.username, 'upload_document', { document_id: created.id, stand_id });
      return res.status(201).json(created);
    }

    if (!url) return sendError(res, 'invalid_request', 'File or url is required', 400);
    try { new URL(url); } catch (_e) { return sendError(res, 'invalid_request', 'Invalid URL', 400); }
    const job = db.prepare(
      `INSERT INTO download_jobs (kind, stand_id, title, description, editable_inline, url, status, created_by, updated_at)
       VALUES ('document', ?, ?, ?, ?, ?, 'queued', ?, ?)`,
    ).run(
      stand_id,
      title || null,
      description,
      isInline ? 1 : 0,
      url,
      created_by,
      new Date().toISOString(),
    );
    logAdminAction(req.user.username, 'queue_document_download', { job_id: job.lastInsertRowid, stand_id });
    processQueue();
    return res.status(202).json({ job_id: job.lastInsertRowid, status: 'queued' });
  } catch (err) {
    return sendError(res, 'invalid_request', err.message);
  }
});

app.get('/api/v1/documents/:id', (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return sendError(res, 'not_found', 'Document not found', 404);
  res.json(doc);
});

app.put('/api/v1/documents/:id', requireAdmin, (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return sendError(res, 'not_found', 'Document not found', 404);
  const { title = doc.title, description = doc.description, editable_inline = !!doc.editable_inline } = req.body || {};
  db.prepare('UPDATE documents SET title = ?, description = ?, editable_inline = ? WHERE id = ?')
    .run(title, description, editable_inline ? 1 : 0, doc.id);
  const updated = db.prepare('SELECT * FROM documents WHERE id = ?').get(doc.id);
  logAdminAction(req.user.username, 'update_document', { document_id: doc.id });
  res.json(updated);
});

app.delete('/api/v1/documents/:id', requireAdmin, (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return sendError(res, 'not_found', 'Document not found', 404);
  db.prepare('DELETE FROM documents WHERE id = ?').run(doc.id);
  const filePath = path.join(storageRoot, doc.stored_name);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  logAdminAction(req.user.username, 'delete_document', { document_id: doc.id });
  res.json({ success: true });
});

app.get('/api/v1/documents/:id/download', (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return sendError(res, 'not_found', 'Document not found', 404);
  const filePath = path.join(storageRoot, doc.stored_name);
  if (!fs.existsSync(filePath)) return sendError(res, 'not_found', 'File missing on server', 404);
  res.download(filePath, doc.file_name);
});

app.get('/api/v1/documents/:id/content', (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return sendError(res, 'not_found', 'Document not found', 404);
  if (!doc.editable_inline) return sendError(res, 'not_allowed', 'Document not editable inline', 400);
  const filePath = path.join(storageRoot, doc.stored_name);
  if (!fs.existsSync(filePath)) return sendError(res, 'not_found', 'File missing on server', 404);
  const content = fs.readFileSync(filePath, 'utf8');
  res.type('text/plain').send(content);
});

app.put('/api/v1/documents/:id/content', requireAdmin, express.text({ type: '*/*', limit: '2mb' }), (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ?').get(req.params.id);
  if (!doc) return sendError(res, 'not_found', 'Document not found', 404);
  if (!doc.editable_inline) return sendError(res, 'not_allowed', 'Document not editable inline', 400);
  const filePath = path.join(storageRoot, doc.stored_name);
  fs.writeFileSync(filePath, req.body || '', 'utf8');
  logAdminAction(req.user.username, 'edit_document_content', { document_id: doc.id });
  res.json({ success: true });
});

// Servers
app.get('/api/v1/stands/:stand_id/servers', (req, res) => {
  const { stand_id } = req.params;
  const { page, page_size, offset } = paginate(req);
  const items = db.prepare('SELECT * FROM servers WHERE stand_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(stand_id, page_size, offset);
  const total = db.prepare('SELECT COUNT(*) as c FROM servers WHERE stand_id = ?').get(stand_id).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.post('/api/v1/stands/:stand_id/servers', requireAdmin, (req, res) => {
  const { stand_id } = req.params;
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(stand_id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  const {
    name,
    inventory_number = '',
    location = '',
    cpu = '',
    ram = '',
    storage = '',
    network = '',
    role = '',
  } = req.body || {};
  if (!name) return sendError(res, 'invalid_request', 'Name is required');
  const now = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO servers (stand_id, name, inventory_number, location, cpu, ram, storage, network, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(stand_id, name, inventory_number, location, cpu, ram, storage, network, role, now, now);
  const created = db.prepare('SELECT * FROM servers WHERE id = ?').get(result.lastInsertRowid);
  logAdminAction(req.user.username, 'create_server', { server_id: created.id, stand_id });
  res.status(201).json(created);
});

app.get('/api/v1/servers', (req, res) => {
  const { q, stand_id, location } = req.query;
  const { page, page_size, offset } = paginate(req);
  const conditions = [];
  const params = [];
  if (stand_id) { conditions.push('stand_id = ?'); params.push(stand_id); }
  if (location) { conditions.push('location LIKE ?'); params.push(`%${location}%`); }
  if (q) { conditions.push('(name LIKE ? OR role LIKE ? OR cpu LIKE ?)'); params.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const items = db.prepare(`SELECT * FROM servers ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, page_size, offset);
  const total = db.prepare(`SELECT COUNT(*) as c FROM servers ${where}`).get(...params).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.get('/api/v1/servers/:id', (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
  if (!server) return sendError(res, 'not_found', 'Server not found', 404);
  res.json(server);
});

app.put('/api/v1/servers/:id', requireAdmin, (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
  if (!server) return sendError(res, 'not_found', 'Server not found', 404);
  const data = { ...server, ...req.body };
  const now = new Date().toISOString();
  db.prepare(
    'UPDATE servers SET name = ?, inventory_number = ?, location = ?, cpu = ?, ram = ?, storage = ?, network = ?, role = ?, updated_at = ? WHERE id = ?',
  ).run(data.name, data.inventory_number, data.location, data.cpu, data.ram, data.storage, data.network, data.role, now, server.id);
  const updated = db.prepare('SELECT * FROM servers WHERE id = ?').get(server.id);
  logAdminAction(req.user.username, 'update_server', { server_id: server.id });
  res.json(updated);
});

app.delete('/api/v1/servers/:id', requireAdmin, (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
  if (!server) return sendError(res, 'not_found', 'Server not found', 404);
  db.prepare('DELETE FROM servers WHERE id = ?').run(server.id);
  logAdminAction(req.user.username, 'delete_server', { server_id: server.id });
  res.json({ success: true });
});

// Distribution products and versions
app.get('/api/v1/stands/:stand_id/distributions', (req, res) => {
  const { stand_id } = req.params;
  const { page, page_size, offset } = paginate(req);
  const items = db.prepare('SELECT * FROM distribution_products WHERE stand_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(stand_id, page_size, offset);
  const total = db.prepare('SELECT COUNT(*) as c FROM distribution_products WHERE stand_id = ?').get(stand_id).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.post('/api/v1/stands/:stand_id/distributions', requireAdmin, (req, res) => {
  const { stand_id } = req.params;
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(stand_id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  const { name, description = '' } = req.body || {};
  if (!name) return sendError(res, 'invalid_request', 'Name is required');
  const now = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO distribution_products (stand_id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)',
  ).run(stand_id, name, description, now, now);
  const created = db.prepare('SELECT * FROM distribution_products WHERE id = ?').get(result.lastInsertRowid);
  logAdminAction(req.user.username, 'create_distribution', { distribution_id: created.id, stand_id });
  res.status(201).json(created);
});

app.get('/api/v1/distributions/:id', (req, res) => {
  const prod = db.prepare('SELECT * FROM distribution_products WHERE id = ?').get(req.params.id);
  if (!prod) return sendError(res, 'not_found', 'Distribution not found', 404);
  res.json(prod);
});

app.put('/api/v1/distributions/:id', requireAdmin, (req, res) => {
  const prod = db.prepare('SELECT * FROM distribution_products WHERE id = ?').get(req.params.id);
  if (!prod) return sendError(res, 'not_found', 'Distribution not found', 404);
  const { name = prod.name, description = prod.description } = req.body || {};
  const now = new Date().toISOString();
  db.prepare('UPDATE distribution_products SET name = ?, description = ?, updated_at = ? WHERE id = ?')
    .run(name, description, now, prod.id);
  const updated = db.prepare('SELECT * FROM distribution_products WHERE id = ?').get(prod.id);
  logAdminAction(req.user.username, 'update_distribution', { distribution_id: prod.id });
  res.json(updated);
});

app.delete('/api/v1/distributions/:id', requireAdmin, (req, res) => {
  const prod = db.prepare('SELECT * FROM distribution_products WHERE id = ?').get(req.params.id);
  if (!prod) return sendError(res, 'not_found', 'Distribution not found', 404);
  db.prepare('DELETE FROM distribution_products WHERE id = ?').run(prod.id);
  logAdminAction(req.user.username, 'delete_distribution', { distribution_id: prod.id });
  res.json({ success: true });
});

app.get('/api/v1/distributions/:id/versions', (req, res) => {
  const { id } = req.params;
  const { page, page_size, offset } = paginate(req);
  const items = db.prepare('SELECT * FROM distribution_versions WHERE product_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(id, page_size, offset);
  const total = db.prepare('SELECT COUNT(*) as c FROM distribution_versions WHERE product_id = ?').get(id).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.post('/api/v1/distributions/:id/versions', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const { id } = req.params;
    const product = db.prepare('SELECT * FROM distribution_products WHERE id = ?').get(id);
    if (!product) return sendError(res, 'not_found', 'Distribution not found', 404);
    const file = req.file;
    const url = req.body?.url;
    const { description = '', is_active = false } = req.body || {};
    const active = is_active === 'true' || is_active === true || is_active === '1';

    if (file) {
      const storedName = file.filename;
      const fileName = file.originalname;
      const result = db.prepare(
        'INSERT INTO distribution_versions (product_id, file_name, file_path, description, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      ).run(id, fileName, storedName, description, active ? 1 : 0, new Date().toISOString());
      const created = db.prepare('SELECT * FROM distribution_versions WHERE id = ?').get(result.lastInsertRowid);
      if (active) {
        db.prepare('UPDATE distribution_versions SET is_active = 0 WHERE product_id = ? AND id != ?').run(id, created.id);
      }
      logAdminAction(req.user.username, 'upload_distribution_version', { version_id: created.id, product_id: id });
      return res.status(201).json(created);
    }

    if (!url) return sendError(res, 'invalid_request', 'File or url is required', 400);
    try { new URL(url); } catch (_e) { return sendError(res, 'invalid_request', 'Invalid URL', 400); }
    const job = db.prepare(
      `INSERT INTO download_jobs (kind, stand_id, product_id, description, is_active, url, status, created_by, updated_at)
       VALUES ('distribution_version', ?, ?, ?, ?, ?, 'queued', ?, ?)`,
    ).run(
      product.stand_id,
      id,
      description,
      active ? 1 : 0,
      url,
      req.user.username || '',
      new Date().toISOString(),
    );
    logAdminAction(req.user.username, 'queue_distribution_download', { job_id: job.lastInsertRowid, product_id: id });
    processQueue();
    return res.status(202).json({ job_id: job.lastInsertRowid, status: 'queued' });
  } catch (err) {
    return sendError(res, 'invalid_request', err.message);
  }
});

app.get('/api/v1/distribution-versions/:id', (req, res) => {
  const version = db.prepare('SELECT * FROM distribution_versions WHERE id = ?').get(req.params.id);
  if (!version) return sendError(res, 'not_found', 'Version not found', 404);
  res.json(version);
});

app.put('/api/v1/distribution-versions/:id', requireAdmin, (req, res) => {
  const version = db.prepare('SELECT * FROM distribution_versions WHERE id = ?').get(req.params.id);
  if (!version) return sendError(res, 'not_found', 'Version not found', 404);
  const { description = version.description, is_active = !!version.is_active } = req.body || {};
  db.prepare('UPDATE distribution_versions SET description = ?, is_active = ? WHERE id = ?')
    .run(description, is_active ? 1 : 0, version.id);
  if (is_active) {
    db.prepare('UPDATE distribution_versions SET is_active = 0 WHERE product_id = ? AND id != ?').run(version.product_id, version.id);
  }
  const updated = db.prepare('SELECT * FROM distribution_versions WHERE id = ?').get(version.id);
  logAdminAction(req.user.username, 'update_distribution_version', { version_id: version.id });
  res.json(updated);
});

app.delete('/api/v1/distribution-versions/:id', requireAdmin, (req, res) => {
  const version = db.prepare('SELECT * FROM distribution_versions WHERE id = ?').get(req.params.id);
  if (!version) return sendError(res, 'not_found', 'Version not found', 404);
  db.prepare('DELETE FROM distribution_versions WHERE id = ?').run(version.id);
  const filePath = path.join(storageRoot, version.file_path);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  logAdminAction(req.user.username, 'delete_distribution_version', { version_id: version.id });
  res.json({ success: true });
});

app.get('/api/v1/distribution-versions/:id/download', (req, res) => {
  const version = db.prepare('SELECT * FROM distribution_versions WHERE id = ?').get(req.params.id);
  if (!version) return sendError(res, 'not_found', 'Version not found', 404);
  const filePath = path.join(storageRoot, version.file_path);
  if (!fs.existsSync(filePath)) return sendError(res, 'not_found', 'File missing on server', 404);
  res.download(filePath, version.file_name);
});

// Download jobs
app.get('/api/v1/downloads', requireAdmin, (req, res) => {
  const { stand_id, kind } = req.query;
  const conditions = [];
  const params = [];
  if (stand_id) { conditions.push('stand_id = ?'); params.push(stand_id); }
  if (kind) { conditions.push('kind = ?'); params.push(kind); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const jobs = db.prepare(`SELECT * FROM download_jobs ${where} ORDER BY created_at DESC LIMIT 200`).all(...params);
  res.json({ items: jobs });
});

app.get('/api/v1/downloads/:id', requireAdmin, (req, res) => {
  const job = db.prepare('SELECT * FROM download_jobs WHERE id = ?').get(req.params.id);
  if (!job) return sendError(res, 'not_found', 'Job not found', 404);
  res.json(job);
});

app.post('/api/v1/downloads/:id/cancel', requireAdmin, (req, res) => {
  const job = db.prepare('SELECT * FROM download_jobs WHERE id = ?').get(req.params.id);
  if (!job) return sendError(res, 'not_found', 'Job not found', 404);
  if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
    return res.json(job);
  }
  cancelJob(job.id);
  res.json({ id: job.id, status: 'cancelled' });
});

// VM groups
app.get('/api/v1/stands/:stand_id/vm-groups', (req, res) => {
  const { stand_id } = req.params;
  const { page, page_size, offset } = paginate(req);
  const items = db.prepare('SELECT * FROM vm_groups WHERE stand_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(stand_id, page_size, offset);
  const total = db.prepare('SELECT COUNT(*) as c FROM vm_groups WHERE stand_id = ?').get(stand_id).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.post('/api/v1/stands/:stand_id/vm-groups', requireAdmin, (req, res) => {
  const { stand_id } = req.params;
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(stand_id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  const { name, description = '' } = req.body || {};
  if (!name) return sendError(res, 'invalid_request', 'Name is required');
  const now = new Date().toISOString();
  const result = db.prepare('INSERT INTO vm_groups (stand_id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .run(stand_id, name, description, now, now);
  const created = db.prepare('SELECT * FROM vm_groups WHERE id = ?').get(result.lastInsertRowid);
  logAdminAction(req.user.username, 'create_vm_group', { vm_group_id: created.id, stand_id });
  res.status(201).json(created);
});

app.get('/api/v1/vm-groups/:id', (req, res) => {
  const group = db.prepare('SELECT * FROM vm_groups WHERE id = ?').get(req.params.id);
  if (!group) return sendError(res, 'not_found', 'VM group not found', 404);
  res.json(group);
});

app.put('/api/v1/vm-groups/:id', requireAdmin, (req, res) => {
  const group = db.prepare('SELECT * FROM vm_groups WHERE id = ?').get(req.params.id);
  if (!group) return sendError(res, 'not_found', 'VM group not found', 404);
  const { name = group.name, description = group.description } = req.body || {};
  const now = new Date().toISOString();
  db.prepare('UPDATE vm_groups SET name = ?, description = ?, updated_at = ? WHERE id = ?')
    .run(name, description, now, group.id);
  const updated = db.prepare('SELECT * FROM vm_groups WHERE id = ?').get(group.id);
  logAdminAction(req.user.username, 'update_vm_group', { vm_group_id: group.id });
  res.json(updated);
});

app.delete('/api/v1/vm-groups/:id', requireAdmin, (req, res) => {
  const group = db.prepare('SELECT * FROM vm_groups WHERE id = ?').get(req.params.id);
  if (!group) return sendError(res, 'not_found', 'VM group not found', 404);
  db.prepare('DELETE FROM vm_groups WHERE id = ?').run(group.id);
  logAdminAction(req.user.username, 'delete_vm_group', { vm_group_id: group.id });
  res.json({ success: true });
});

// VMs
app.get('/api/v1/stands/:stand_id/vms', (req, res) => {
  const { stand_id } = req.params;
  const { page, page_size, offset } = paginate(req);
  const items = db.prepare('SELECT * FROM vms WHERE stand_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(stand_id, page_size, offset)
    .map((vm) => ({ ...vm, ips: parseArray(vm.ips) }));
  const total = db.prepare('SELECT COUNT(*) as c FROM vms WHERE stand_id = ?').get(stand_id).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.post('/api/v1/stands/:stand_id/vms', requireAdmin, (req, res) => {
  const { stand_id } = req.params;
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(stand_id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  const {
    group_id = null,
    name,
    description = '',
    ips = [],
    os = '',
    role = '',
    ssh_port = 22,
  } = req.body || {};
  if (!name) return sendError(res, 'invalid_request', 'Name is required');
  const now = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO vms (stand_id, group_id, name, description, ips, os, role, ssh_port, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(stand_id, group_id || null, name, description, JSON.stringify(parseArray(ips)), os, role, ssh_port || 22, now, now);
  const created = db.prepare('SELECT * FROM vms WHERE id = ?').get(result.lastInsertRowid);
  logAdminAction(req.user.username, 'create_vm', { vm_id: created.id, stand_id });
  res.status(201).json({ ...created, ips: parseArray(created.ips) });
});

app.get('/api/v1/vms', (req, res) => {
  const { q, stand_id, group_id, ip } = req.query;
  const { page, page_size, offset } = paginate(req);
  const conditions = [];
  const params = [];
  if (stand_id) { conditions.push('stand_id = ?'); params.push(stand_id); }
  if (group_id) { conditions.push('group_id = ?'); params.push(group_id); }
  if (ip) { conditions.push('ips LIKE ?'); params.push(`%${ip}%`); }
  if (q) { conditions.push('(name LIKE ? OR description LIKE ? OR role LIKE ? OR os LIKE ?)'); params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`); }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const items = db.prepare(`SELECT * FROM vms ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, page_size, offset)
    .map((vm) => ({ ...vm, ips: parseArray(vm.ips) }));
  const total = db.prepare(`SELECT COUNT(*) as c FROM vms ${where}`).get(...params).c;
  res.json(buildListResponse(items, total, page, page_size));
});

app.get('/api/v1/vms/:id', (req, res) => {
  const vm = db.prepare('SELECT * FROM vms WHERE id = ?').get(req.params.id);
  if (!vm) return sendError(res, 'not_found', 'VM not found', 404);
  res.json({ ...vm, ips: parseArray(vm.ips) });
});

app.put('/api/v1/vms/:id', requireAdmin, (req, res) => {
  const vm = db.prepare('SELECT * FROM vms WHERE id = ?').get(req.params.id);
  if (!vm) return sendError(res, 'not_found', 'VM not found', 404);
  const data = { ...vm, ...req.body };
  const now = new Date().toISOString();
  db.prepare(
    'UPDATE vms SET stand_id = ?, group_id = ?, name = ?, description = ?, ips = ?, os = ?, role = ?, ssh_port = ?, updated_at = ? WHERE id = ?',
  ).run(
    data.stand_id,
    data.group_id || null,
    data.name,
    data.description,
    JSON.stringify(parseArray(data.ips)),
    data.os,
    data.role,
    data.ssh_port || 22,
    now,
    vm.id,
  );
  const updated = db.prepare('SELECT * FROM vms WHERE id = ?').get(vm.id);
  logAdminAction(req.user.username, 'update_vm', { vm_id: vm.id });
  res.json({ ...updated, ips: parseArray(updated.ips) });
});

app.delete('/api/v1/vms/:id', requireAdmin, (req, res) => {
  const vm = db.prepare('SELECT * FROM vms WHERE id = ?').get(req.params.id);
  if (!vm) return sendError(res, 'not_found', 'VM not found', 404);
  db.prepare('DELETE FROM vms WHERE id = ?').run(vm.id);
  logAdminAction(req.user.username, 'delete_vm', { vm_id: vm.id });
  res.json({ success: true });
});

// Graph
app.get('/api/v1/stands/:stand_id/graph', (req, res) => {
  const { stand_id } = req.params;
  const nodes = db.prepare('SELECT * FROM graph_nodes WHERE stand_id = ?').all(stand_id);
  const edges = db.prepare('SELECT * FROM graph_edges WHERE stand_id = ?').all(stand_id);
  res.json({ nodes, edges });
});

app.put('/api/v1/stands/:stand_id/graph', requireAdmin, (req, res) => {
  const { stand_id } = req.params;
  const stand = db.prepare('SELECT * FROM stands WHERE id = ?').get(stand_id);
  if (!stand) return sendError(res, 'not_found', 'Stand not found', 404);
  const { nodes = [], edges = [] } = req.body || {};
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM graph_edges WHERE stand_id = ?').run(stand_id);
    db.prepare('DELETE FROM graph_nodes WHERE stand_id = ?').run(stand_id);
    nodes.forEach((n) => {
      db.prepare('INSERT INTO graph_nodes (id, stand_id, vm_id, x, y) VALUES (?, ?, ?, ?, ?)').run(
        n.id || null,
        stand_id,
        n.vm_id,
        n.x,
        n.y,
      );
    });
    edges.forEach((e) => {
      db.prepare('INSERT INTO graph_edges (id, stand_id, source_node_id, target_node_id, description) VALUES (?, ?, ?, ?, ?)')
        .run(e.id || null, stand_id, e.source_node_id, e.target_node_id, e.description || '');
    });
  });
  tx();
  logAdminAction(req.user.username, 'save_graph', { stand_id });
  res.json({ success: true });
});

app.post('/api/v1/stands/:stand_id/graph/nodes', requireAdmin, (req, res) => {
  const { stand_id } = req.params;
  const { vm_id, x, y } = req.body || {};
  if (!vm_id) return sendError(res, 'invalid_request', 'vm_id is required');
  const result = db.prepare('INSERT INTO graph_nodes (stand_id, vm_id, x, y) VALUES (?, ?, ?, ?)').run(stand_id, vm_id, x, y);
  const node = db.prepare('SELECT * FROM graph_nodes WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(node);
});

app.put('/api/v1/graph-nodes/:id', requireAdmin, (req, res) => {
  const node = db.prepare('SELECT * FROM graph_nodes WHERE id = ?').get(req.params.id);
  if (!node) return sendError(res, 'not_found', 'Graph node not found', 404);
  const { x = node.x, y = node.y } = req.body || {};
  db.prepare('UPDATE graph_nodes SET x = ?, y = ? WHERE id = ?').run(x, y, node.id);
  const updated = db.prepare('SELECT * FROM graph_nodes WHERE id = ?').get(node.id);
  res.json(updated);
});

app.delete('/api/v1/graph-nodes/:id', requireAdmin, (req, res) => {
  const node = db.prepare('SELECT * FROM graph_nodes WHERE id = ?').get(req.params.id);
  if (!node) return sendError(res, 'not_found', 'Graph node not found', 404);
  db.prepare('DELETE FROM graph_nodes WHERE id = ?').run(node.id);
  res.json({ success: true });
});

app.post('/api/v1/stands/:stand_id/graph/edges', requireAdmin, (req, res) => {
  const { stand_id } = req.params;
  const { source_node_id, target_node_id, description = '' } = req.body || {};
  if (!source_node_id || !target_node_id) return sendError(res, 'invalid_request', 'source_node_id and target_node_id are required');
  const result = db.prepare(
    'INSERT INTO graph_edges (stand_id, source_node_id, target_node_id, description) VALUES (?, ?, ?, ?)',
  ).run(stand_id, source_node_id, target_node_id, description);
  const edge = db.prepare('SELECT * FROM graph_edges WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json(edge);
});

app.put('/api/v1/graph-edges/:id', requireAdmin, (req, res) => {
  const edge = db.prepare('SELECT * FROM graph_edges WHERE id = ?').get(req.params.id);
  if (!edge) return sendError(res, 'not_found', 'Graph edge not found', 404);
  const { description = edge.description } = req.body || {};
  db.prepare('UPDATE graph_edges SET description = ? WHERE id = ?').run(description, edge.id);
  const updated = db.prepare('SELECT * FROM graph_edges WHERE id = ?').get(edge.id);
  res.json(updated);
});

app.delete('/api/v1/graph-edges/:id', requireAdmin, (req, res) => {
  const edge = db.prepare('SELECT * FROM graph_edges WHERE id = ?').get(req.params.id);
  if (!edge) return sendError(res, 'not_found', 'Graph edge not found', 404);
  db.prepare('DELETE FROM graph_edges WHERE id = ?').run(edge.id);
  res.json({ success: true });
});

// Search
app.get('/api/v1/search', (req, res) => {
  const { q, type } = req.query;
  if (!q) return sendError(res, 'invalid_request', 'q is required');
  const like = `%${q}%`;
  const allowed = ['stand', 'vm', 'server', 'distribution', 'document'];
  const target = type && allowed.includes(type) ? type : null;
  const result = {};
  if (!target || target === 'stand') {
    result.stands = db.prepare('SELECT * FROM stands WHERE name LIKE ? OR description LIKE ? LIMIT 20').all(like, like)
      .map((s) => ({ ...s, tags: parseArray(s.tags) }));
  }
  if (!target || target === 'vm') {
    result.vms = db.prepare('SELECT * FROM vms WHERE name LIKE ? OR description LIKE ? OR ips LIKE ? LIMIT 20').all(like, like, like)
      .map((vm) => ({ ...vm, ips: parseArray(vm.ips) }));
  }
  if (!target || target === 'server') {
    result.servers = db.prepare('SELECT * FROM servers WHERE name LIKE ? OR role LIKE ? OR location LIKE ? LIMIT 20').all(like, like, like);
  }
  if (!target || target === 'distribution') {
    result.distributions = db.prepare('SELECT * FROM distribution_products WHERE name LIKE ? OR description LIKE ? LIMIT 20').all(like, like);
  }
  if (!target || target === 'document') {
    result.documents = db.prepare('SELECT * FROM documents WHERE title LIKE ? OR description LIKE ? LIMIT 20').all(like, like);
  }
  res.json(result);
});

app.get('/api/v1/health', (_req, res) => res.json({ status: 'ok' }));

app.use((err, _req, res, _next) => {
  logLine('error', err.message || 'Unhandled error');
  res.status(500).json({ error: 'internal_error', message: 'Unexpected error' });
});

app.listen(port, () => {
  console.log(`Stand catalog API listening on port ${port}`);
});
