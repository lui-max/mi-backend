const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root1234",
  database: "mi_app"
});

db.connect(function(err) {
  if (err) console.log("Error:", err);
  else console.log("Conectado!");
});

app.post("/registro", function(req, res) {
  const email = req.body.email;
  const pass = req.body.password;
  const hashPass = bcrypt.hashSync(pass, 10);
  db.query("INSERT INTO auth (email, password) VALUES (?, ?)", [email, hashPass], function(err) {
    if (err) return res.json({ error: err });
    res.json({ mensaje: "Registrado!" });
  });
});

app.post("/login", function(req, res) {
  const email = req.body.email;
  const pass = req.body.password;
  db.query("SELECT * FROM auth WHERE email = ?", [email], function(err, rows) {
    if (err) return res.json({ error: err });
    if (rows.length === 0) return res.json({ mensaje: "No existe" });
    const ok = bcrypt.compareSync(pass, rows[0].password);
    if (!ok) return res.json({ mensaje: "Password incorrecto" });
    const token = jwt.sign({ id: rows[0].id }, "secreto123", { expiresIn: "1d" });
    res.json({ mensaje: "Login ok", token: token });
  });
});

app.listen(3001, function() {
  console.log("Servidor en puerto 3001");
});