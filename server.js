const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "techzone-change-this-secret";

app.use(cors());
app.use(express.json());

const dataDir = path.join(__dirname, "data");
const usersFile = path.join(dataDir, "users.json");
const messagesFile = path.join(dataDir, "messages.json");

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, "[]");
if (!fs.existsSync(messagesFile)) fs.writeFileSync(messagesFile, "[]");

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, message: "Login required" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "TechZone API",
    version: "1.0.0",
    message: "API is running",
    endpoints: {
      signup: "POST /api/auth/signup",
      login: "POST /api/auth/login",
      me: "GET /api/auth/me",
      contact: "POST /api/contact"
    }
  });
});

app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "OK" });
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: "Name, email and password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const users = readJson(usersFile);

    if (users.some(u => u.email === normalizedEmail)) {
      return res.status(409).json({ success: false, message: "Email is already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      id: Date.now().toString(),
      name: String(name).trim(),
      email: normalizedEmail,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    users.push(user);
    writeJson(usersFile, users);

    res.status(201).json({
      success: true,
      message: "Account created successfully",
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email and password are required" });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const users = readJson(usersFile);
    const user = users.find(u => u.email === normalizedEmail);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ success: false, message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: { id: user.id, name: user.name, email: user.email }
    });
  } catch {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json({ success: true, user: req.user });
});

app.post("/api/contact", (req, res) => {
  try {
    const { name, email, message } = req.body;
    if (!name || !email || !message) {
      return res.status(400).json({ success: false, message: "Name, email and message are required" });
    }

    const messages = readJson(messagesFile);
    const item = {
      id: Date.now().toString(),
      name: String(name).trim(),
      email: String(email).trim().toLowerCase(),
      message: String(message).trim(),
      createdAt: new Date().toISOString()
    };

    messages.push(item);
    writeJson(messagesFile, messages);

    res.status(201).json({
      success: true,
      message: "Message received successfully",
      id: item.id
    });
  } catch {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`TechZone API running on http://localhost:${PORT}`);
});
