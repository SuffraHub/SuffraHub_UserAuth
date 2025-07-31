const express = require('express');
const app = express();
const port = 8000;
const cors = require('cors');

require('dotenv').config();
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.use(cors());
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
  res.json({ message: 'main'});
});

app.post('/register', async (req, res) => {
  const { username, email, password, name, surname } = req.body;

  if (!username || !email || !password || !name || !surname) {
    return res.status(400).json({ message: 'Required field not provided' });
  }

  try {
    // Check if username already exists
    const checkQuery = `SELECT COUNT(*) AS count FROM users WHERE username = ?`;
    connection.query(checkQuery, [username], async (err, results) => {
      if (err) {
        console.error('MySQL error during username check:', err);
        return res.status(500).json({ message: 'Database error during username check' });
      }

      if (results[0].count > 0) {
        return res.status(409).json({ message: 'User with this username already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      const insertQuery = `
        INSERT INTO users (username, password, email, permissions, name, surname)
        VALUES (?, ?, ?, 5, ?, ?)
      `;

      connection.query(insertQuery, [username, hashedPassword, email, name, surname], (err, result) => {
        if (err) {
          console.error('MySQL error during insert:', err);
          return res.status(500).json({ message: 'Registration failed' });
        }

        return res.status(201).json({ message: 'User registered' });
      });
    });

  } catch (err) {
    console.error('Unexpected error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});



app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'No username or password'});
  }

  const findUserQuery = 'SELECT * FROM users WHERE username = ? LIMIT 1';
  connection.query(findUserQuery, [username], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Server error'});
    }
    if (results.length === 0) {
      return res.status(401).json({ message: 'Incorrect username or password'});
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error'});
      }
      if (!isMatch) {
        return res.status(401).json({ message: 'Incorrect username or password'});
      }

      const updateLoginQuery = 'UPDATE users SET last_login = NOW() WHERE username = ?';
      connection.query(updateLoginQuery, [username], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'Login update error'});
        }

        res.send('Logged in successfully');
      });
    });
  });
});

app.post('/delete', (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).send('Missing username');
  }

  const deleteUserQuery = 'DELETE FROM users WHERE username = ?';
  connection.query(deleteUserQuery, [username], (err, result) => {
    if (err) {
      console.error('Błąd MySQL:', err);
      return res.status(500).send('User deletion error');
    }

    if (result.affectedRows === 0) {
      return res.status(404).send('User not found');
    }

    res.send('User deleted successfully');
  });
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
