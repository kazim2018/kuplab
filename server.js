/**
 * КУпАП + Фабули — сервер з SQLite і захищеною адмінкою
 *
 * ENV:
 *   PORT=3000
 *   ADMIN_PASSWORD=ваш_пароль          (обов'язково змінити!)
 *   ADMIN_SECRET=довгий_випадковий_рядок
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const multer = require('multer');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'kupfab-admin-change-me';
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(24).toString('hex');
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const DB_PATH = path.join(DATA_DIR, 'kupfab.db');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS offenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article TEXT NOT NULL,
    part TEXT DEFAULT '',
    fabula TEXT DEFAULT '',
    protocol INTEGER DEFAULT 0,
    postanova INTEGER DEFAULT 0,
    detention INTEGER DEFAULT 0,
    presence INTEGER DEFAULT 0,
    judge TEXT DEFAULT '',
    term TEXT DEFAULT '',
    sanction TEXT DEFAULT '',
    image TEXT DEFAULT '',
    sort_order INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS pdr (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article TEXT DEFAULT '',
    label TEXT DEFAULT '',
    pdr TEXT DEFAULT '',
    fabula TEXT DEFAULT '',
    sanction TEXT DEFAULT '',
    data_json TEXT DEFAULT '{}'
  );
  CREATE TABLE IF NOT EXISTS general_norms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article TEXT DEFAULT '',
    title TEXT DEFAULT '',
    note TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS npu (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article TEXT DEFAULT '',
    title TEXT DEFAULT '',
    section TEXT DEFAULT '',
    body TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS fire (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT DEFAULT '',
    subtitle TEXT DEFAULT '',
    cat TEXT DEFAULT '',
    icon TEXT DEFAULT '',
    body TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS fabulas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article TEXT DEFAULT '',
    label TEXT DEFAULT '',
    fabula TEXT DEFAULT '',
    sanction TEXT DEFAULT '',
    category TEXT DEFAULT '',
    judge TEXT DEFAULT '',
    pdr TEXT DEFAULT '',
    data_json TEXT DEFAULT '{}'
  );
  CREATE INDEX IF NOT EXISTS idx_offenses_article ON offenses(article);
`);

function seedIfEmpty() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM offenses').get().c;
  if (count > 0) return;
  const seedPath = path.join(DATA_DIR, 'seed.json');
  if (!fs.existsSync(seedPath)) {
    console.warn('Немає seed.json — база порожня');
    return;
  }
  const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
  const insOff = db.prepare(`INSERT INTO offenses
    (article, part, fabula, protocol, postanova, detention, presence, judge, term, sanction, image, sort_order)
    VALUES (@article, @part, @fabula, @protocol, @postanova, @detention, @presence, @judge, @term, @sanction, @image, @sort_order)`);

  const tx = db.transaction(() => {
    (seed.offensesData || []).forEach((o, i) => {
      insOff.run({
        article: String(o.article || ''),
        part: String(o.part || ''),
        fabula: o.fabula || '',
        protocol: o.protocol ? 1 : 0,
        postanova: o.postanova ? 1 : 0,
        detention: o.detention ? 1 : 0,
        presence: o.presence ? 1 : 0,
        judge: o.judge || '',
        term: o.term || '',
        sanction: o.sanction || '',
        image: o.image || '',
        sort_order: i,
      });
    });
    const insPdr = db.prepare(`INSERT INTO pdr (article, label, pdr, fabula, sanction, data_json) VALUES (?,?,?,?,?,?)`);
    (seed.pdrData || []).forEach((x) => {
      insPdr.run(x.article || '', x.label || '', x.pdr || '', x.fabula || '', x.sanction || '', JSON.stringify(x));
    });
    const insG = db.prepare(`INSERT INTO general_norms (article, title, note) VALUES (?,?,?)`);
    (seed.generalData || []).forEach((x) => insG.run(x.article || '', x.title || '', x.note || ''));
    const insN = db.prepare(`INSERT INTO npu (article, title, section, body) VALUES (?,?,?,?)`);
    (seed.npuLawData || []).forEach((x) => insN.run(x.article || '', x.title || '', x.section || '', x.body || ''));
    const insF = db.prepare(`INSERT INTO fire (title, subtitle, cat, icon, body) VALUES (?,?,?,?,?)`);
    (seed.fireData || []).forEach((x) => insF.run(x.title || '', x.subtitle || '', x.cat || '', x.icon || '', x.body || ''));
    const insFab = db.prepare(`INSERT INTO fabulas (article, label, fabula, sanction, category, judge, pdr, data_json) VALUES (?,?,?,?,?,?,?,?)`);
    (seed.allFabulasData || seed.publicOffensesFabulas || []).forEach((x) => {
      insFab.run(x.article || '', x.label || '', x.fabula || '', x.sanction || '', x.category || '', x.judge || '', x.pdr || '', JSON.stringify(x));
    });
  });
  tx();
  console.log('База заповнена з seed.json');
}
seedIfEmpty();

/* ---- auth tokens (in-memory + signed cookie) ---- */
const sessions = new Map(); // token -> { exp }

function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}
function signToken(token) {
  const h = crypto.createHmac('sha256', ADMIN_SECRET).update(token).digest('hex');
  return token + '.' + h;
}
function verifyToken(signed) {
  if (!signed || !signed.includes('.')) return null;
  const [token, sig] = signed.split('.');
  const expect = crypto.createHmac('sha256', ADMIN_SECRET).update(token).digest('hex');
  if (sig !== expect) return null;
  const s = sessions.get(token);
  if (!s || s.exp < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return token;
}
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
  const cookieTok = req.cookies?.admin_token;
  const token = verifyToken(bearer || cookieTok);
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  req.adminToken = token;
  next();
}

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
      cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
    },
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Only images'));
    cb(null, true);
  },
});

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use('/uploads', express.static(UPLOAD_DIR));

/* ---------- PUBLIC API ---------- */
app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.get('/api/offenses', (_req, res) => {
  const rows = db.prepare('SELECT * FROM offenses ORDER BY sort_order, article, part').all();
  res.json(rows.map(mapOffense));
});

app.get('/api/pdr', (_req, res) => {
  res.json(db.prepare('SELECT * FROM pdr ORDER BY id').all().map(mapPdr));
});

app.get('/api/general', (_req, res) => {
  res.json(db.prepare('SELECT * FROM general_norms ORDER BY id').all());
});

app.get('/api/npu', (_req, res) => {
  res.json(db.prepare('SELECT * FROM npu ORDER BY id').all());
});

app.get('/api/fire', (_req, res) => {
  res.json(db.prepare('SELECT * FROM fire ORDER BY id').all());
});

app.get('/api/fabulas', (_req, res) => {
  res.json(db.prepare('SELECT * FROM fabulas ORDER BY id').all().map(mapFab));
});

app.get('/api/all', (_req, res) => {
  res.json({
    offensesData: db.prepare('SELECT * FROM offenses ORDER BY sort_order, article, part').all().map(mapOffense),
    pdrData: db.prepare('SELECT * FROM pdr ORDER BY id').all().map(mapPdr),
    generalData: db.prepare('SELECT * FROM general_norms ORDER BY id').all(),
    npuLawData: db.prepare('SELECT * FROM npu ORDER BY id').all(),
    fireData: db.prepare('SELECT * FROM fire ORDER BY id').all(),
    allFabulasData: db.prepare('SELECT * FROM fabulas ORDER BY id').all().map(mapFab),
  });
});

function mapOffense(r) {
  return {
    id: r.id,
    article: r.article,
    part: r.part,
    fabula: r.fabula,
    protocol: !!r.protocol,
    postanova: !!r.postanova,
    detention: !!r.detention,
    presence: !!r.presence,
    judge: r.judge,
    term: r.term,
    sanction: r.sanction,
    image: r.image,
  };
}
function mapPdr(r) {
  try {
    const j = JSON.parse(r.data_json || '{}');
    return { id: r.id, ...j, article: r.article, label: r.label, pdr: r.pdr, fabula: r.fabula, sanction: r.sanction };
  } catch {
    return { id: r.id, article: r.article, label: r.label, pdr: r.pdr, fabula: r.fabula, sanction: r.sanction };
  }
}
function mapFab(r) {
  try {
    const j = JSON.parse(r.data_json || '{}');
    return { id: r.id, ...j, article: r.article, label: r.label, fabula: r.fabula, sanction: r.sanction, category: r.category, judge: r.judge, pdr: r.pdr };
  } catch {
    return { id: r.id, article: r.article, label: r.label, fabula: r.fabula, sanction: r.sanction, category: r.category, judge: r.judge, pdr: r.pdr };
  }
}

/* ---------- AUTH ---------- */
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Невірний пароль' });
  }
  const token = makeToken();
  sessions.set(token, { exp: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  const signed = signToken(token);
  res.cookie('admin_token', signed, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.json({ token: signed, ok: true });
});

app.post('/api/admin/logout', requireAdmin, (req, res) => {
  sessions.delete(req.adminToken);
  res.clearCookie('admin_token');
  res.json({ ok: true });
});

app.get('/api/admin/me', requireAdmin, (_req, res) => {
  res.json({ ok: true, role: 'admin' });
});

/* ---------- ADMIN CRUD: offenses ---------- */
app.post('/api/admin/offenses', requireAdmin, (req, res) => {
  const o = req.body || {};
  const r = db.prepare(`INSERT INTO offenses
    (article, part, fabula, protocol, postanova, detention, presence, judge, term, sanction, image, sort_order)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    String(o.article || ''),
    String(o.part || ''),
    o.fabula || '',
    o.protocol ? 1 : 0,
    o.postanova ? 1 : 0,
    o.detention ? 1 : 0,
    o.presence ? 1 : 0,
    o.judge || '',
    o.term || '',
    o.sanction || '',
    o.image || '',
    o.sort_order || 0
  );
  const row = db.prepare('SELECT * FROM offenses WHERE id=?').get(r.lastInsertRowid);
  res.json(mapOffense(row));
});

app.put('/api/admin/offenses/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const o = req.body || {};
  db.prepare(`UPDATE offenses SET
    article=?, part=?, fabula=?, protocol=?, postanova=?, detention=?, presence=?,
    judge=?, term=?, sanction=?, image=? WHERE id=?`).run(
    String(o.article || ''),
    String(o.part || ''),
    o.fabula || '',
    o.protocol ? 1 : 0,
    o.postanova ? 1 : 0,
    o.detention ? 1 : 0,
    o.presence ? 1 : 0,
    o.judge || '',
    o.term || '',
    o.sanction || '',
    o.image || '',
    id
  );
  const row = db.prepare('SELECT * FROM offenses WHERE id=?').get(id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(mapOffense(row));
});

app.delete('/api/admin/offenses/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM offenses WHERE id=?').run(Number(req.params.id));
  res.json({ ok: true });
});

/* bulk replace article parts */
app.put('/api/admin/articles/:articleNumber', requireAdmin, (req, res) => {
  const articleNumber = String(req.params.articleNumber);
  const { title, authority, tags, parts, coverImage } = req.body || {};
  const judge =
    authority === 'police' ? 'Поліція' : authority === 'commission' ? 'Адмінкомісія' : 'Суд';

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM offenses WHERE article=?').run(articleNumber);
    const ins = db.prepare(`INSERT INTO offenses
      (article, part, fabula, protocol, postanova, detention, presence, judge, term, sanction, image, sort_order)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
    (parts || []).forEach((p, i) => {
      ins.run(
        articleNumber,
        String(p.partNumber || ''),
        p.fabula || title || '',
        p.protocol || (p.process || '').includes('Протокол') ? 1 : 0,
        p.postanova || (p.process || '').includes('Постанова') ? 1 : 0,
        p.detention ? 1 : 0,
        p.presence ? 1 : 0,
        p.judge || judge,
        p.term || '',
        p.sanction || '',
        p.image || coverImage || '',
        i
      );
    });
  });
  tx();
  const rows = db.prepare('SELECT * FROM offenses WHERE article=? ORDER BY sort_order').all(articleNumber);
  res.json(rows.map(mapOffense));
});

app.delete('/api/admin/articles/:articleNumber', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM offenses WHERE article=?').run(String(req.params.articleNumber));
  res.json({ ok: true });
});

/* generic table helper */
function crudTable(table, publicFields) {
  app.post(`/api/admin/${table}`, requireAdmin, (req, res) => {
    const body = req.body || {};
    if (table === 'pdr') {
      const r = db.prepare(`INSERT INTO pdr (article,label,pdr,fabula,sanction,data_json) VALUES (?,?,?,?,?,?)`).run(
        body.article || '', body.label || '', body.pdr || '', body.fabula || '', body.sanction || '', JSON.stringify(body)
      );
      return res.json({ id: r.lastInsertRowid, ...body });
    }
    if (table === 'general') {
      const r = db.prepare(`INSERT INTO general_norms (article,title,note) VALUES (?,?,?)`).run(body.article || '', body.title || '', body.note || '');
      return res.json({ id: r.lastInsertRowid, ...body });
    }
    if (table === 'npu') {
      const r = db.prepare(`INSERT INTO npu (article,title,section,body) VALUES (?,?,?,?)`).run(body.article || '', body.title || '', body.section || '', body.body || '');
      return res.json({ id: r.lastInsertRowid, ...body });
    }
    if (table === 'fire') {
      const r = db.prepare(`INSERT INTO fire (title,subtitle,cat,icon,body) VALUES (?,?,?,?,?)`).run(body.title || '', body.subtitle || '', body.cat || '', body.icon || '', body.body || '');
      return res.json({ id: r.lastInsertRowid, ...body });
    }
    if (table === 'fabulas') {
      const r = db.prepare(`INSERT INTO fabulas (article,label,fabula,sanction,category,judge,pdr,data_json) VALUES (?,?,?,?,?,?,?,?)`).run(
        body.article || '', body.label || '', body.fabula || '', body.sanction || '', body.category || '', body.judge || '', body.pdr || '', JSON.stringify(body)
      );
      return res.json({ id: r.lastInsertRowid, ...body });
    }
    res.status(400).json({ error: 'unknown table' });
  });

  app.put(`/api/admin/${table}/:id`, requireAdmin, (req, res) => {
    const id = Number(req.params.id);
    const body = req.body || {};
    if (table === 'pdr') {
      db.prepare(`UPDATE pdr SET article=?,label=?,pdr=?,fabula=?,sanction=?,data_json=? WHERE id=?`).run(
        body.article || '', body.label || '', body.pdr || '', body.fabula || '', body.sanction || '', JSON.stringify(body), id
      );
    } else if (table === 'general') {
      db.prepare(`UPDATE general_norms SET article=?,title=?,note=? WHERE id=?`).run(body.article || '', body.title || '', body.note || '', id);
    } else if (table === 'npu') {
      db.prepare(`UPDATE npu SET article=?,title=?,section=?,body=? WHERE id=?`).run(body.article || '', body.title || '', body.section || '', body.body || '', id);
    } else if (table === 'fire') {
      db.prepare(`UPDATE fire SET title=?,subtitle=?,cat=?,icon=?,body=? WHERE id=?`).run(body.title || '', body.subtitle || '', body.cat || '', body.icon || '', body.body || '', id);
    } else if (table === 'fabulas') {
      db.prepare(`UPDATE fabulas SET article=?,label=?,fabula=?,sanction=?,category=?,judge=?,pdr=?,data_json=? WHERE id=?`).run(
        body.article || '', body.label || '', body.fabula || '', body.sanction || '', body.category || '', body.judge || '', body.pdr || '', JSON.stringify(body), id
      );
    }
    res.json({ id, ...body });
  });

  app.delete(`/api/admin/${table}/:id`, requireAdmin, (req, res) => {
    const map = { pdr: 'pdr', general: 'general_norms', npu: 'npu', fire: 'fire', fabulas: 'fabulas' };
    const t = map[table];
    if (!t) return res.status(400).json({ error: 'bad table' });
    db.prepare(`DELETE FROM ${t} WHERE id=?`).run(Number(req.params.id));
    res.json({ ok: true });
  });
}

crudTable('pdr');
crudTable('general');
crudTable('npu');
crudTable('fire');
crudTable('fabulas');

/* upload image */
app.post('/api/admin/upload', requireAdmin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = '/uploads/' + req.file.filename;
  res.json({ url });
});

/* ---------- static: admin only via /admin (no link from public) ---------- */
app.use('/admin', (req, res, next) => {
  // serve admin SPA files; auth is enforced by API
  next();
}, express.static(path.join(__dirname, 'public', 'admin')));

app.get('/admin', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});

/* public site */
app.use(express.static(path.join(__dirname, 'public', 'site')));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  const index = path.join(__dirname, 'public', 'site', 'index.html');
  if (fs.existsSync(index)) return res.sendFile(index);
  res.status(404).send('Not found');
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Server error' });
});

app.listen(PORT, () => {
  console.log(`КУпАП server http://localhost:${PORT}`);
  console.log(`Адмінка: http://localhost:${PORT}/admin`);
  console.log(`Пароль: ${ADMIN_PASSWORD === 'kupfab-admin-change-me' ? 'КУПОМО! Змініть ADMIN_PASSWORD' : '(з ENV)'}`);
});
