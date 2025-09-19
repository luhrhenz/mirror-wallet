// server.js (CommonJS version)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const { open } = require("sqlite");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

let db;

// Initialize SQLite
(async () => {
  try {
    db = await open({
      filename: "./wallet.db",
      driver: sqlite3.Database,
    });

    // Create users table if not exists
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        keystore TEXT NOT NULL
      )
    `);

    console.log("✅ Database initialized and ready");
  } catch (err) {
    console.error("❌ Database initialization failed:", err.message);
    process.exit(1);
  }
})();

// Signup endpoint
app.post("/signup", async (req, res) => {
  if (!db) {
    return res.status(503).json({ error: "Database not ready" });
  }

  try {
    const { username, password, keystore } = req.body;

    if (!username || !password || !keystore) {
      return res.status(400).json({ error: "Missing required fields: username, password, keystore" });
    }

    // Check if user exists
    const existingUser = await db.get("SELECT id FROM users WHERE username = ?", [username]);
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hash = await bcrypt.hash(password, 12); // Increased salt rounds

    const result = await db.run(
      "INSERT INTO users (username, password_hash, keystore) VALUES (?, ?, ?)",
      [username, hash, keystore]
    );

    if (result.changes > 0) {
      res.status(201).json({ message: "User created successfully", userId: result.lastID });
    } else {
      res.status(500).json({ error: "Failed to create user" });
    }
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT') {
      res.status(409).json({ error: "Username already taken" });
    } else {
      console.error("❌ Signup error:", err.message);
      res.status(500).json({ error: "Server error during signup. Please try again." });
    }
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  if (!db) {
    return res.status(503).json({ error: "Database not ready" });
  }

  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing required fields: username, password" });
    }

    const user = await db.get("SELECT id, username, password_hash, keystore FROM users WHERE username = ?", [
      username,
    ]);

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    res.json({
      message: "Login successful",
      username: user.username,
      keystore: user.keystore,
      userId: user.id
    });
  } catch (err) {
    console.error("❌ Login error:", err.message);
    res.status(500).json({ error: "Server error during login. Please try again." });
  }
});

app.post("/import", async (req, res) => {
  if (!db) {
    return res.status(503).json({ error: "Database not ready" });
  }

  try {
    const { username, password, newKeystore } = req.body;

    if (!username || !password || !newKeystore) {
      return res.status(400).json({ error: "Missing required fields: username, password, newKeystore" });
    }

    const user = await db.get("SELECT id, password_hash FROM users WHERE username = ?", [username]);

    if (!user) {
      return res.status(404).json({ error: "User not found. Please sign up first." });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    await db.run("UPDATE users SET keystore = ? WHERE id = ?", [newKeystore, user.id]);

    res.json({
      message: "Wallet imported successfully",
      userId: user.id,
      username: username
    });
  } catch (err) {
    console.error("❌ Import error:", err.message);
    res.status(500).json({ error: "Server error during import. Please try again." });
  }
});

app.post("/get-keystore", async (req, res) => {
  if (!db) {
    return res.status(503).json({ error: "Database not ready" });
  }

  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing required fields: username, password" });
    }

    const user = await db.get("SELECT id, username, password_hash, keystore FROM users WHERE username = ?", [username]);

    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    res.json({
      message: "Keystore retrieved successfully",
      username: user.username,
      keystore: user.keystore,
      userId: user.id
    });
  } catch (err) {
    console.error("❌ Get keystore error:", err.message);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



// Graceful shutdown
process.on('SIGINT', async () => {
  if (db) {
    await db.close();
    console.log("✅ Database connection closed");
  }
  process.exit(0);
});
