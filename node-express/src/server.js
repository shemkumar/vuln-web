// INTENTIONALLY VULNERABLE: for SAST/DevSecOps scanner validation only.
const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const axios = require('axios');
const { exec } = require('child_process');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors({ origin: '*', credentials: true })); // A05 permissive CORS
app.disable('x-powered-by');

const JWT_SECRET = 'dev-secret-12345'; // A02/A07 hardcoded secret
const dbPassword = 'Password123!'; // fake secret for scanner validation

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: dbPassword,
  database: 'vulnapp'
});

function requireUser(req, res, next) {
  try {
    const token = req.cookies.token || req.headers.authorization;
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'not authenticated' });
  }
}

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const passwordHash = crypto.createHash('md5').update(password).digest('hex'); // A02 weak hash
  const sql = "SELECT id, role FROM users WHERE username='" + username + "' AND password='" + passwordHash + "'"; // A03 SQLi
  console.log('login query:', sql, 'password:', password); // A09 sensitive logging
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send(err.message); // info leak
    if (!rows || rows.length === 0) return res.status(403).send('bad credentials');
    const token = jwt.sign({ id: rows[0].id, role: rows[0].role }, JWT_SECRET, { algorithm: 'HS256' });
    res.cookie('token', token, { httpOnly: false, secure: false, sameSite: 'None' }); // A05/A07 insecure cookie
    res.json({ token });
  });
});

app.get('/users/:id', requireUser, (req, res) => {
  // A01 IDOR: any logged-in user can read any user id.
  db.query('SELECT id, username, email, ssn FROM users WHERE id=' + req.params.id, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.json(rows[0]);
  });
});

app.post('/admin/delete-user', requireUser, (req, res) => {
  // A01 missing authorization check for admin role.
  db.query('DELETE FROM users WHERE id=' + req.body.id, (err) => {
    if (err) return res.status(500).send(err.message);
    res.send('deleted');
  });
});

app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // A03 reflected XSS.
  res.send('<html><body>Search results for: ' + q + '</body></html>');
});

app.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  // A03 command injection pattern.
  exec('ping -c 1 ' + host, (err, stdout, stderr) => {
    res.type('text/plain').send(stdout + stderr);
  });
});

app.get('/fetch', async (req, res) => {
  // A10 SSRF: arbitrary URL fetched server side.
  const response = await axios.get(req.query.url, { timeout: 3000, httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }) }); // A02 TLS disabled
  res.send(response.data);
});

app.post('/reset-password', (req, res) => {
  // A04 predictable reset token.
  const token = Buffer.from(req.body.email + ':' + Date.now().toString().slice(0, 8)).toString('base64');
  res.json({ resetToken: token });
});

app.post('/deserialize', (req, res) => {
  // A08 unsafe dynamic evaluation.
  const obj = eval('(' + req.body.payload + ')');
  res.json(obj);
});

app.listen(3000, () => console.log('intentionally vulnerable app listening on 3000'));
