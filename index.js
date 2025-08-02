require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 8000;

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());


app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60, // 1h
    sameSite: 'lax'
  }
}));

// DB connection
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

// === Middlewarey autoryzacji ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    connection.query(
      'SELECT * FROM user_tokens WHERE token = ? AND expires_at > NOW()',
      [token],
      (err, results) => {
        if (err || results.length === 0) return res.sendStatus(401);
        req.user = user;
        next();
      }
    );
  });
}

function authenticateSession(req, res, next) {
  if (!req.session.user) return res.status(401).json({ message: 'Not authenticated' });
  req.user = req.session.user;
  next();
}

// === ENDPOINTY ===

app.get('/', (req, res) => {
  res.json({ message: 'main' });
});

app.post('/register', async (req, res) => {
  const { username, email, password, name, surname } = req.body;

  if (!username || !email || !password || !name || !surname) {
    return res.status(400).json({ message: 'Required field not provided' });
  }

  try {
    const checkQuery = `SELECT COUNT(*) AS count FROM users WHERE username = ?`;
    connection.query(checkQuery, [username], async (err, results) => {
      if (err) return res.status(500).json({ message: 'Database error' });

      if (results[0].count > 0) {
        return res.status(409).json({ message: 'User with this username already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertQuery = `
        INSERT INTO users (username, password, email, permissions, name, surname)
        VALUES (?, ?, ?, 5, ?, ?)
      `;
      connection.query(insertQuery, [username, hashedPassword, email, name, surname], (err) => {
        if (err) return res.status(500).json({ message: 'Registration failed' });
        return res.status(201).json({ message: 'User registered' });
      });
    });

  } catch (err) {
    console.error('Unexpected error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// TODO REGISTER TO TENANT!!!

app.post('/login', (req, res) => {
  const { username, password, remember } = req.body;
  const userAgent = req.headers['user-agent'];
  const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!username || !password) {
    return res.status(400).json({ message: 'No username or password' });
  }

  const findUserQuery = 'SELECT * FROM users WHERE username = ? LIMIT 1';
  connection.query(findUserQuery, [username], (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ message: 'Incorrect username or password' });
    }

    const user = results[0];

    bcrypt.compare(password, user.password, async (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ message: 'Incorrect username or password' });
      }

      const updateLoginQuery = 'UPDATE users SET last_login = NOW() WHERE username = ?';
      connection.query(updateLoginQuery, [username]);

      // Ustawiamy dane w sesji zawsze, bez względu na remember
      req.session.user_id = user.id;
      req.session.company_id = user.company_id;

      if (remember) {
        const tokenPayload = { id: user.id, username: user.username };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '7d' });
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        const insertTokenQuery = `
          INSERT INTO user_tokens (user_id, token, expires_at, user_agent, ip_address, created_at)
          VALUES (?, ?, ?, ?, ?, NOW())
        `;

        connection.query(insertTokenQuery, [user.id, token, expiresAt, userAgent, ipAddress], (err) => {
          if (err) return res.status(500).json({ message: 'Login failed' });
          // Wysyłamy token w ciasteczku httpOnly lub w body, do wyboru (tu w body)
          return res.json({ success: true, message: 'Logged in with token', token });
        });
      } else {
        return res.json({ success: true, message: 'Logged in with session' });
      }
    });
  });
});

// Middleware do sprawdzania JWT z headera Authorization
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return next(); // brak tokena, idź dalej do sprawdzania sesji

  const token = authHeader.split(' ')[1];
  if (!token) return next();

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next();
    req.jwtUser = user; // dane z tokena
    next();
  });
}

app.get('/user-info', authenticateToken, (req, res) => {
  let userId = null;

  if (req.session && req.session.user_id) {
    userId = req.session.user_id;
  } else if (req.jwtUser) {
    userId = req.jwtUser.id;
  } else {
    return res.json({ loggedIn: false });
  }

  connection.query(
    'SELECT company_id, permissions FROM users WHERE id = ?',
    [userId],
    (err, results) => {
      if (err) {
        console.error('DB error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (results.length === 0) {
        return res.status(404).json({ loggedIn: false, error: 'User not found' });
      }

      const { company_id, permissions } = results[0];

      res.json({
        loggedIn: true,
        method: req.session && req.session.user_id ? 'session' : 'token',
        user_id: userId,
        username: req.jwtUser ? req.jwtUser.username : null,
        company_id,
        permissions: Number(permissions),
      });
    }
  );
});





app.post('/editUser', async (req, res) => {
  const { userId, username, email, password, name, surname } = req.body;

  if (!userId || !username || !email || !name || !surname) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    const checkQuery = `SELECT * FROM users WHERE id = ?`;
    connection.query(checkQuery, [userId], async (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ message: 'User not found' });
      }

      const usernameCheckQuery = `SELECT id FROM users WHERE username = ? AND id != ?`;
      connection.query(usernameCheckQuery, [username, userId], async (err, userCheckResults) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        if (userCheckResults.length > 0) {
          return res.status(409).json({ message: 'Username already in use by another user' });
        }

        let hashedPassword = results[0].password;
        if (password) {
          hashedPassword = await bcrypt.hash(password, 10);
        }

        const updateQuery = `
          UPDATE users
          SET username = ?, password = ?, email = ?, name = ?, surname = ?
          WHERE id = ?
        `;
        const values = [username, hashedPassword, email, name, surname, userId];
        connection.query(updateQuery, values, (err) => {
          if (err) return res.status(500).json({ message: 'User update failed' });
          return res.status(200).json({ message: 'User updated successfully' });
        });
      });
    });
  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/delete', (req, res) => {
  const { username } = req.body;

  if (!username) return res.status(400).send('Missing username');

  const deleteUserQuery = 'DELETE FROM users WHERE username = ?';
  connection.query(deleteUserQuery, [username], (err, result) => {
    if (err) return res.status(500).send('User deletion error');
    if (result.affectedRows === 0) return res.status(404).send('User not found');
    res.send('User deleted successfully');
  });
});

// // Przykład: dostęp tylko dla zalogowanych (token lub sesja)
// app.get('/dashboard', (req, res, next) => {
//   if (req.headers.authorization) {
//     authenticateToken(req, res, () => {
//       res.json({ message: 'Token OK', user: req.user });
//     });
//   } else if (req.session.user_id) {
//     res.json({ message: 'Session OK', user: req.session.user_id });
//   } else {
//     res.status(401).json({ message: 'Not authenticated' });
//   }
// });

app.post('/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (token) {
    // 🔒 Logout z tokenem
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid token' });
      }

      const deleteQuery = 'DELETE FROM user_tokens WHERE token = ?';
      connection.query(deleteQuery, [token], (err) => {
        if (err) {
          console.error('Token deletion error:', err);
          return res.status(500).json({ message: 'Logout failed' });
        }

        return res.json({ message: 'Logged out (token)' });
      });
    });

  } else if (req.session.user_id) {
    // 🧠 Logout z sesji
    req.session.destroy(err => {
      if (err) {
        return res.status(500).json({ message: 'Logout failed' });
      }
      res.clearCookie('connect.sid'); // opcjonalnie
      return res.json({ message: 'Logged out (session)' });
    });

  } 
  // else {
  //   return res.status(400).json({ message: 'Not logged in' });
  // }
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
