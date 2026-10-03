const express = require('express');
const { Pool } = require('pg');

const app = express();
const pool = new Pool();

app.get('/orders', async (req, res) => {
  const customer = req.query.customer;
  const found = await pool.query("SELECT * FROM orders WHERE customer = '" + customer + "'");
  const bound = await pool.query('SELECT * FROM orders WHERE customer = $1', [customer]);
  res.json({ found: found.rows, bound: bound.rows });
});

module.exports = app;
