const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Sequelize, DataTypes } = require("sequelize");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectOptions: {
    ssl: { require: true, rejectUnauthorized: false }
  }
});

// User model
const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  password_hash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  keystore: {
    type: DataTypes.TEXT,
    allowNull: false
  }
});

// Initialize DB
(async () => {
  try {
    await sequelize.authenticate();
    await sequelize.sync();
    console.log("✅ PostgreSQL connected and synced");
  } catch (err) {
    console.error("❌ Database connection failed:", err.message);
    process.exit(1);
  }
})();

// Signup endpoint
app.post("/signup", async (req, res) => {
  try {
    const { username, password, keystore } = req.body;

    if (!username || !password || !keystore) {
      return res.status(400).json({ error: "Missing required fields: username, password, keystore" });
    }

    // Check if user exists
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hash = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      password_hash: hash,
      keystore
    });

    res.status(201).json({ message: "User created successfully", userId: user.id });
  } catch (err) {
    console.error("❌ Signup error:", err.message);
    if (err.name === 'SequelizeUniqueConstraintError') {
      res.status(409).json({ error: "Username already taken" });
    } else {
      res.status(500).json({ error: "Server error during signup. Please try again." });
    }
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing required fields: username, password" });
    }

    const user = await User.findOne({ where: { username } });
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

// Import endpoint
app.post("/import", async (req, res) => {
  try {
    const { username, password, newKeystore } = req.body;

    if (!username || !password || !newKeystore) {
      return res.status(400).json({ error: "Missing required fields: username, password, newKeystore" });
    }

    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.status(404).json({ error: "User not found. Please sign up first." });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    await user.update({ keystore: newKeystore });

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

// Get keystore endpoint
app.post("/get-keystore", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Missing required fields: username, password" });
    }

    const user = await User.findOne({ where: { username } });
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
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  await sequelize.close();
  console.log("✅ Database connection closed");
  process.exit(0);
});
