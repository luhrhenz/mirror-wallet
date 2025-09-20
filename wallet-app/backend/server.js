require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const winston = require("winston");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ====== LOGGER CONFIG ======
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'wallet-backend' },
  transports: [
    new winston.transports.File({
      filename: process.env.NODE_ENV === 'production' ? 'error.log' : 'logs/error.log',
      level: 'error'
    }),
    new winston.transports.File({
      filename: process.env.NODE_ENV === 'production' ? 'combined.log' : 'logs/combined.log'
    }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

// ====== JWT CONFIG ======
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// JWT helper functions
function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }

  req.userId = decoded.userId;
  next();
}

// ====== ENCRYPTION CONFIG ======
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-32-character-encryption-key!!'; // 32 bytes
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;

// Encryption helper functions
function encrypt(text) {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipherGCM(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'utf8'));
    cipher.setAAD(Buffer.from('wallet-app', 'utf8'));

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();
    return iv.toString('hex') + ':' + encrypted + ':' + authTag.toString('hex');
  } catch (error) {
    logger.error('Encryption error:', error);
    throw new Error('Failed to encrypt data');
  }
}

function decrypt(encryptedText) {
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const authTag = Buffer.from(parts[2], 'hex');

    const decipher = crypto.createDecipherGCM(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'utf8'));
    decipher.setAAD(Buffer.from('wallet-app', 'utf8'));
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    logger.error('Decryption error:', error);
    throw new Error('Failed to decrypt data');
  }
}

// ====== CORS CONFIG ======
const allowedOrigins = [
  "http://localhost:3000",
  "https://mrrorwallet.netlify.app",
  "https://wallet-backend-jiph.onrender.com"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

// ====== JSON PARSER ======
app.use(express.json());

// ====== MONGO CONNECTION ======
const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URI;
if (!mongoUri) {
  logger.error("❌ Missing MONGODB_URI environment variable.");
  process.exit(1); // Exit if no MongoDB URI
}

mongoose.connect(mongoUri)
  .then(() => logger.info("✅ Connected to MongoDB Atlas"))
  .catch(err => logger.error("❌ MongoDB connection error:", err));

// ====== USER SCHEMA ======
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3, maxlength: 50 },
  password_hash: { type: String, required: true },
  keystore: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// ====== RATE LIMITING ======
const createRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 10 : 100, // 10 for production, 100 for development
  message: { error: "Too many requests, try later." },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  handler: (req, res) => {
    logger.warn("Rate limit exceeded", {
      ip: req.ip,
      url: req.url,
      userAgent: req.get("User-Agent")
    });
    res.status(429).json({ error: "Too many requests, try later." });
  }
});

// ====== INPUT VALIDATORS ======
const USERNAME_REGEX = /^[a-zA-Z0-9_-]{3,50}$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
const KEYSTORE_REGEX = /^\{[\s\S]*\}$/; // Basic JSON object validation

function validateSignupInput(req, res, next) {
  const { username, password, keystore } = req.body;

  // Username validation
  if (!username || !USERNAME_REGEX.test(username)) {
    return res.status(400).json({
      error: "Username must be 3-50 characters, alphanumeric with underscores and hyphens only"
    });
  }

  // Password validation
  if (!password || !PASSWORD_REGEX.test(password)) {
    return res.status(400).json({
      error: "Password must be at least 8 characters with uppercase, lowercase, number, and special character"
    });
  }

  // Keystore validation
  if (!keystore || keystore.length < 100 || !KEYSTORE_REGEX.test(keystore.trim())) {
    return res.status(400).json({
      error: "Invalid keystore data - must be a valid JSON object with minimum 100 characters"
    });
  }

  // Additional JSON validation
  try {
    JSON.parse(keystore);
  } catch (err) {
    return res.status(400).json({ error: "Keystore must be valid JSON" });
  }

  next();
}

function validateLoginInput(req, res, next) {
  const { username, password } = req.body;

  if (!username || !USERNAME_REGEX.test(username)) {
    return res.status(400).json({
      error: "Username must be 3-50 characters, alphanumeric with underscores and hyphens only"
    });
  }

  if (!password || password.length < 1) {
    return res.status(400).json({ error: "Password is required" });
  }

  next();
}

function validateImportInput(req, res, next) {
  const { newKeystore } = req.body;

  if (!newKeystore || newKeystore.length < 100 || !KEYSTORE_REGEX.test(newKeystore.trim())) {
    return res.status(400).json({
      error: "Invalid keystore data - must be a valid JSON object with minimum 100 characters"
    });
  }

  // Additional JSON validation
  try {
    JSON.parse(newKeystore);
  } catch (err) {
    return res.status(400).json({ error: "Keystore must be valid JSON" });
  }

  next();
}

// ====== ROUTES ======

// Signup
app.post("/signup", createRateLimit, validateSignupInput, async (req, res) => {
  try {
    const { username, password, keystore } = req.body;
    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: "Username already exists" });

    const hash = await bcrypt.hash(password, 12);
    const encryptedKeystore = encrypt(keystore);
    const newUser = await User.create({ username, password_hash: hash, keystore: encryptedKeystore });

    logger.info("User created successfully", { userId: newUser._id, username });
    res.status(201).json({ message: "User created", userId: newUser._id });
  } catch (err) {
    logger.error("Signup error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Server error during signup" });
  }
});

// Login
app.post("/login", createRateLimit, validateLoginInput, async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: "Invalid username or password" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid username or password" });

    const token = generateToken(user._id);
    const decryptedKeystore = decrypt(user.keystore);
    logger.info("User logged in successfully", { userId: user._id, username });

    res.json({
      message: "Login successful",
      token,
      userId: user._id,
      username,
      keystore: decryptedKeystore
    });
  } catch (err) {
    logger.error("Login error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Server error during login" });
  }
});

// Import wallet
app.post("/import", authenticateToken, validateImportInput, async (req, res) => {
  try {
    const { newKeystore } = req.body;

    if (!newKeystore || newKeystore.length < 100) {
      return res.status(400).json({ error: "Invalid keystore data" });
    }

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const encryptedKeystore = encrypt(newKeystore);
    user.keystore = encryptedKeystore;
    await user.save();

    logger.info("Wallet imported successfully", { userId: user._id });
    res.json({ message: "Wallet imported", userId: user._id });
  } catch (err) {
    logger.error("Import error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Server error during import" });
  }
});

// Get keystore
app.post("/get-keystore", createRateLimit, authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const decryptedKeystore = decrypt(user.keystore);
    logger.info("Keystore retrieved successfully", { userId: user._id });
    res.json({ keystore: decryptedKeystore, userId: user._id, username: user.username });
  } catch (err) {
    logger.error("Get keystore error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Server error" });
  }
});

// User profile
app.get("/user/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("username createdAt");
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({ userId: user._id, username: user.username, createdAt: user.createdAt });
  } catch (err) {
    logger.error("User lookup error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Server error" });
  }
});

// Backup (admin only)
app.get("/admin/backup", async (req, res) => {
  try {
    if (process.env.NODE_ENV === "production" &&
        req.headers.authorization !== "Bearer " + process.env.ADMIN_TOKEN) {
      return res.status(403).json({ error: "Admin access required" });
    }

    const users = await User.find().select("username createdAt updatedAt");
    res.json({ backup: { total: users.length, users } });
  } catch (err) {
    logger.error("Backup error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Server error" });
  }
});

// Health check
app.get("/health", (req, res) => {
  const health = {
    status: "OK",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    environment: process.env.NODE_ENV || "development",
    version: "1.0.0"
  };

  const statusCode = mongoose.connection.readyState === 1 ? 200 : 503;
  res.status(statusCode).json(health);
});

// API status endpoint
app.get("/api/health", (req, res) => {
  res.json({
    message: "Wallet API is running",
    version: "1.0.0",
    environment: process.env.NODE_ENV || "development",
    endpoints: [
      "POST /signup",
      "POST /login",
      "POST /import",
      "POST /get-keystore",
      "GET /user/:id",
      "GET /health"
    ]
  });
});

// ====== ERROR HANDLING ======
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// ====== SERVER START ======
app.listen(PORT, () => {
  logger.info(`🚀 Server running on port ${PORT}`);
  logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`🔗 Health check: http://localhost:${PORT}/health`);
  logger.info(`🔗 API status: http://localhost:${PORT}/api/health`);
});
