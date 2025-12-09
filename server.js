// NanoTag Mexico backend - simple demo API for Render

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

// ---------- Basic setup ----------
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

if (!fs.existsSync(path.join(__dirname, 'uploads'))) {
  fs.mkdirSync(path.join(__dirname, 'uploads'));
}

// ---------- SQLite DB ----------
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      plan_type TEXT DEFAULT 'BASIC',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      asset_type TEXT,
      make TEXT,
      model TEXT,
      year TEXT,
      serial_vin TEXT,
      nano_tag_id TEXT,
      image_path TEXT,
      status TEXT DEFAULT 'ACTIVE',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS theft_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      asset_id INTEGER,
      incident_date TEXT,
      incident_location TEXT,
      police_station TEXT,
      officer_name TEXT,
      report_number TEXT,
      narrative TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (asset_id) REFERENCES assets(id)
    )
  `);
});

// ---------- Auth helpers ----------
function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, plan_type: user.plan_type },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const [, token] = header.split(' ');
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ---------- Multer for uploads ----------
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (_, file, cb) => {
    const uniq = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniq + path.extname(file.originalname || '.jpg'));
  }
});
const upload = multer({ storage });

// ---------- Simple root ----------
app.get('/', (req, res) => {
  res.json({ status: 'NanoTag Mexico backend OK' });
});

// ---------- Auth routes ----------

// Register
app.post('/api/auth/register', (req, res) => {
  const { name, email, password, planType } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const hash = bcrypt.hashSync(password, 10);
  const plan = planType === 'FULL' ? 'FULL' : 'BASIC';

  db.run(
    `INSERT INTO users (name, email, password_hash, plan_type) VALUES (?, ?, ?, ?)`,
    [name || '', email.toLowerCase(), hash, plan],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.status(400).json({ error: 'Email already registered' });
        }
        return res.status(500).json({ error: 'DB error' });
      }
      db.get(`SELECT id, name, email, plan_type, created_at FROM users WHERE id = ?`, [this.lastID], (err2, user) => {
        if (err2 || !user) return res.status(500).json({ error: 'DB error' });
        const token = createToken(user);
        res.json({ token, user });
      });
    }
  );
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  db.get(`SELECT * FROM users WHERE email = ?`, [email.toLowerCase()], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      plan_type: user.plan_type,
      created_at: user.created_at
    };
    const token = createToken(safeUser);
    res.json({ token, user: safeUser });
  });
});

// Current user
app.get('/api/me', authRequired, (req, res) => {
  db.get(
    `SELECT id, name, email, plan_type, created_at FROM users WHERE id = ?`,
    [req.user.id],
    (err, user) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json(user);
    }
  );
});

// ---------- Subscription upgrade (fake payment) ----------
app.post('/api/users/upgrade', authRequired, (req, res) => {
  db.run(
    `UPDATE users SET plan_type = 'FULL' WHERE id = ?`,
    [req.user.id],
    function (err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ success: true });
    }
  );
});

// ---------- Asset routes ----------

// Create asset (Full users)
app.post('/api/assets', authRequired, upload.single('image'), (req, res) => {
  if (req.user.plan_type !== 'FULL') {
    return res.status(403).json({ error: 'Full plan required' });
  }

  const {
    asset_type,
    make,
    model,
    year,
    serial_vin,
    nano_tag_id
  } = req.body;

  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

  db.run(
    `INSERT INTO assets (user_id, asset_type, make, model, year, serial_vin, nano_tag_id, image_path)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      req.user.id,
      asset_type || '',
      make || '',
      model || '',
      year || '',
      serial_vin || '',
      nano_tag_id || '',
      imagePath
    ],
    function (err) {
      if (err) return res.status(500).json({ error: 'DB error' });

      db.get(`SELECT * FROM assets WHERE id = ?`, [this.lastID], (err2, asset) => {
        if (err2 || !asset) return res.status(500).json({ error: 'DB error' });
        res.json(asset);
      });
    }
  );
});

// List assets for current user
app.get('/api/assets', authRequired, (req, res) => {
  db.all(
    `SELECT * FROM assets WHERE user_id = ? ORDER BY created_at DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json(rows);
    }
  );
});

// ---------- Theft reports ----------

// Create theft report
app.post('/api/thefts', authRequired, (req, res) => {
  const {
    asset_id,
    incident_date,
    incident_location,
    police_station,
    officer_name,
    report_number,
    narrative
  } = req.body;

  if (!asset_id) return res.status(400).json({ error: 'asset_id is required' });

  db.run(
    `INSERT INTO theft_reports
      (user_id, asset_id, incident_date, incident_location, police_station, officer_name, report_number, narrative)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      req.user.id,
      asset_id,
      incident_date || '',
      incident_location || '',
      police_station || '',
      officer_name || '',
      report_number || '',
      narrative || ''
    ],
    function (err) {
      if (err) return res.status(500).json({ error: 'DB error' });

      // mark asset as stolen
      db.run(`UPDATE assets SET status = 'STOLEN' WHERE id = ?`, [asset_id]);

      db.get(`SELECT * FROM theft_reports WHERE id = ?`, [this.lastID], (err2, report) => {
        if (err2 || !report) return res.status(500).json({ error: 'DB error' });
        res.json(report);
      });
    }
  );
});

// Generate PDF for theft report (two URL variants for safety)
function sendTheftPdf(req, res) {
  const id = req.params.id;
  const sql = `
    SELECT tr.*, a.asset_type, a.make, a.model, a.year, a.serial_vin, a.nano_tag_id,
           u.name AS owner_name, u.email AS owner_email
    FROM theft_reports tr
    JOIN assets a ON tr.asset_id = a.id
    JOIN users u ON tr.user_id = u.id
    WHERE tr.id = ?
  `;
  db.get(sql, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Report not found' });

    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="theft-report-${id}.pdf"`);

    doc.fontSize(18).text('NanoTag Mexico - Theft Report', { underline: true });
    doc.moveDown();

    doc.fontSize(12).text(`Report ID: ${row.id}`);
    doc.text(`Date created: ${row.created_at}`);
    doc.moveDown();

    doc.fontSize(14).text('Owner details', { underline: true });
    doc.fontSize(12).text(`Name: ${row.owner_name}`);
    doc.text(`Email: ${row.owner_email}`);
    doc.moveDown();

    doc.fontSize(14).text('Asset details', { underline: true });
    doc.fontSize(12).text(`Type: ${row.asset_type}`);
    doc.text(`Make / Model: ${row.make} ${row.model}`);
    doc.text(`Year: ${row.year}`);
    doc.text(`Serial / VIN: ${row.serial_vin}`);
    doc.text(`NanoTag ID: ${row.nano_tag_id}`);
    doc.moveDown();

    doc.fontSize(14).text('Incident details', { underline: true });
    doc.fontSize(12).text(`Incident date: ${row.incident_date}`);
    doc.text(`Location: ${row.incident_location}`);
    doc.text(`Police station: ${row.police_station}`);
    doc.text(`Officer: ${row.officer_name}`);
    doc.text(`Police report number: ${row.report_number}`);
    doc.moveDown();

    doc.fontSize(14).text('Narrative', { underline: true });
    doc.fontSize(12).text(row.narrative || 'No additional information supplied.');
    doc.moveDown(2);

    doc.fontSize(10).text(
      'This document is automatically generated by NanoTag Mexico based on information supplied by the owner.',
      { align: 'center' }
    );

    doc.end();
    doc.pipe(res);
  });
}

app.get('/api/thefts/:id/pdf', sendTheftPdf);
app.get('/api/theft-reports/:id/pdf', sendTheftPdf); // alias

// ---------- Police lookup ----------
app.get('/api/police/lookup', (req, res) => {
  const { nanoTagId } = req.query;
  if (!nanoTagId) return res.status(400).json({ error: 'nanoTagId query parameter required' });

  const sql = `
    SELECT a.*, u.name AS owner_name, u.email AS owner_email,
           tr.id AS theft_id, tr.created_at AS theft_created_at,
           tr.incident_date, tr.incident_location, tr.police_station, tr.officer_name, tr.report_number
    FROM assets a
    JOIN users u ON a.user_id = u.id
    LEFT JOIN theft_reports tr ON tr.asset_id = a.id
    WHERE a.nano_tag_id = ?
    ORDER BY tr.created_at DESC NULLS LAST
    LIMIT 1
  `;

  db.get(sql, [nanoTagId], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'No asset found for this NanoTag ID' });
    res.json(row);
  });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`NanoTag Mexico backend listening on port ${PORT}`);
});
