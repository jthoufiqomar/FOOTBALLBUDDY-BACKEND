require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) {
    console.error('MySQL connection error:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL');
});

// Middleware to verify JWT and admin (blog owner)
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Only allow the admin user to write blogs
const ADMIN_USERNAME = 'admin'; // Change this to your username

// Blog CRUD APIs
app.get('/api/posts', (req, res) => {
  db.query('SELECT * FROM posts', (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get('/api/posts/:id', (req, res) => {
  db.query('SELECT * FROM posts WHERE id = ?', [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'Post not found' });
    res.json(results[0]);
  });
});

// Protect create, update, delete routes
app.post('/api/posts', authenticate, (req, res) => {
  if (req.user.username !== ADMIN_USERNAME) return res.status(403).json({ error: 'Only the admin can create posts' });
  const { title, content } = req.body;
  db.query('INSERT INTO posts (title, content) VALUES (?, ?)', [title, content], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: result.insertId, title, content });
  });
});

app.put('/api/posts/:id', authenticate, (req, res) => {
  if (req.user.username !== ADMIN_USERNAME) return res.status(403).json({ error: 'Only the admin can update posts' });
  const { title, content } = req.body;
  db.query('UPDATE posts SET title = ?, content = ? WHERE id = ?', [title, content, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: req.params.id, title, content });
  });
});

app.delete('/api/posts/:id', authenticate, (req, res) => {
  if (req.user.username !== ADMIN_USERNAME) return res.status(403).json({ error: 'Only the admin can delete posts' });
  db.query('DELETE FROM posts WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(204).send();
  });
});

// User registration
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username already exists' });
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ id: result.insertId, username });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// User login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET || 'secret', { expiresIn: '1d' });
    res.json({ token });
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
