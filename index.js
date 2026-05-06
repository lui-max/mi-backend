require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

db.connect(function(err) {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conectado a MySQL correctamente');
});

// Protección contra fuerza bruta
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Demasiados intentos, espera 15 minutos" }
});
app.use("/login", limiter);


app.post("/registro", function(req, res) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email y password son requeridos" });
  }
  const hashPass = bcrypt.hashSync(password, 10);
  db.query("INSERT INTO auth (email, password) VALUES (?, ?)", [email, hashPass], function(err) {
    if (err) return res.status(500).json({ error: "Error al registrar" });
    res.status(201).json({ mensaje: "Registrado exitosamente!" });
  });
});

app.post("/login", function(req, res) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email y password son requeridos" });
  }
  db.query("SELECT * FROM auth WHERE email = ?", [email], function(err, rows) {
    if (err) return res.status(500).json({ error: "Error del servidor" });
    if (rows.length === 0) return res.status(404).json({ error: "Usuario no existe" });
    const ok = bcrypt.compareSync(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: "Password incorrecto" });
    const token = jwt.sign({ id: rows[0].id }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ mensaje: "Login exitoso!", token });
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, function() {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});