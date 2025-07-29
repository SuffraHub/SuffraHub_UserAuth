const express = require('express');
const app = express();
const port = 8000;

require('dotenv').config();
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(express.json());

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

connection.connect(err => {
  if (err) {
    console.error('DB connection error:', err.stack);
    return;
  }
  console.log('Connected to MySQL');
});


app.get('/', (req, res) => {
  res.send('main');
});

app.post('/register', async (req, res) => {
  const { username, email, password, name, surname } = req.body;

  if (!username || !email || !password || !name || !surname) {
    return res.status(400).send('Required field not provided');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO users (username, password, email, permissions, name, surname)
      VALUES (?, ?, ?, 5, ?, ?)
    `;

    connection.query(query, [username, hashedPassword, email, name, surname], (err, result) => {
      if (err) {
        console.error('MySQL error:', err);
        return res.status(500).send('Registration failed');
      }
      res.status(201).send('User registered');
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});


app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('No username or password');
  }

  const findUserQuery = 'SELECT * FROM users WHERE username = ? LIMIT 1';
  connection.query(findUserQuery, [username], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Server error');
    }
    if (results.length === 0) {
      return res.status(401).send('Incorrect username or password');
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Server error');
      }
      if (!isMatch) {
        return res.status(401).send('Incorrect username or password');
      }

      const updateLoginQuery = 'UPDATE users SET last_login = NOW() WHERE username = ?';
      connection.query(updateLoginQuery, [username], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Login update error');
        }

        res.send('Logged in successfully');
      });
    });
  });
});


app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
