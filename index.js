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
  const { username, email, password, imie, nazwisko } = req.body;

  if (!username || !email || !password || !imie || !nazwisko) {
    return res.status(400).send('Brakuje wymaganych pól');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO users (username, password, email, permissions, imie, nazwisko)
      VALUES (?, ?, ?, 5, ?, ?)
    `;

    connection.query(query, [username, hashedPassword, email, imie, nazwisko], (err, result) => {
      if (err) {
        console.error('Błąd MySQL:', err);
        return res.status(500).send('Błąd rejestracji użytkownika');
      }
      res.status(201).send('Użytkownik zarejestrowany');
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Błąd serwera');
  }
});


app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send('Brakuje nazwy użytkownika lub hasła');
  }

  const findUserQuery = 'SELECT * FROM users WHERE username = ? LIMIT 1';
  connection.query(findUserQuery, [username], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Błąd serwera');
    }
    if (results.length === 0) {
      return res.status(401).send('Nieprawidłowa nazwa użytkownika lub hasło');
    }

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Błąd serwera');
      }
      if (!isMatch) {
        return res.status(401).send('Nieprawidłowa nazwa użytkownika lub hasło');
      }

      const updateLoginQuery = 'UPDATE users SET last_login = NOW() WHERE username = ?';
      connection.query(updateLoginQuery, [username], (err) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Błąd aktualizacji logowania');
        }

        res.send('Zalogowano pomyślnie');
      });
    });
  });
});


app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
