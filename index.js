const express = require('express')
const app = express()
const port = 8000

require('dotenv').config();

const mysql = require('mysql');

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});


connection.connect();

connection.query("SELECT * FROM `companies`", (err, rows, fields) => {
  if (err) throw err

  for(row of rows) {
    console.log(row.id, row.name, row.description)
  }
})

connection.end()

app.get('/', (req, res) => {
  res.send('Hello world!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
