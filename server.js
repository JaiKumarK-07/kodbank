import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const db = new sqlite3.Database('kodbank.db');
const SECRET_KEY = 'KodBankSecretKey';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Promisify database operations
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

// Initialize database
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS KodUser (
      uid INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      password TEXT NOT NULL,
      balance REAL DEFAULT 100000,
      phone TEXT NOT NULL,
      role TEXT DEFAULT 'customer'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS UserToken (
      tid INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT NOT NULL,
      uid INTEGER NOT NULL,
      expiry INTEGER NOT NULL,
      FOREIGN KEY (uid) REFERENCES KodUser(uid)
    )
  `);
});

// Registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, phone } = req.body;
    
    if (!username || !email || !password || !phone) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    
    await dbRun(
      `INSERT INTO KodUser (username, email, password, phone, balance, role)
       VALUES (?, ?, ?, ?, 100000, 'customer')`,
      [username, email, hashedPassword, phone]
    );
    
    res.json({ success: true, message: 'Registration successful' });
  } catch (error) {
    if (error.message.includes('UNIQUE constraint failed')) {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await dbGet('SELECT * FROM KodUser WHERE username = ?', [username]);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { username: user.username, role: user.role },
      SECRET_KEY,
      { subject: user.username, expiresIn: '1h' }
    );

    const expiry = Date.now() + 3600000;
    await dbRun('INSERT INTO UserToken (token, uid, expiry) VALUES (?, ?, ?)', [token, user.uid, expiry]);

    res.cookie('authToken', token, { httpOnly: true, maxAge: 3600000 });
    res.json({ success: true, message: 'Login successful' });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get balance endpoint
app.get('/api/balance', async (req, res) => {
  try {
    const token = req.cookies.authToken;
    
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const decoded = jwt.verify(token, SECRET_KEY);
    const user = await dbGet('SELECT balance FROM KodUser WHERE username = ?', [decoded.username]);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ balance: user.balance });
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// Get current user endpoint
app.get('/api/user', (req, res) => {
  try {
    const token = req.cookies.authToken;
    
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ username: decoded.username });
  } catch (error) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`KodBank server running on port ${PORT}`);
});
