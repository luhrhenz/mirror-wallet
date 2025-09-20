const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { Sequelize, DataTypes } = require("sequelize");

const app = express();
const PORT = process.env.PORT || 3000;

// Environment variables validation
const requiredEnvVars = ['DATABASE_URL', 'NODE_ENV'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error(`❌ Missing required environment variables: ${missingEnvVars.join(', ')}`);
  console.error('Please set these in your Render dashboard');
}

// CORS configuration - Production-ready with specific origins
const allowedOrigins = [
  "http://localhost:3000", 
  "https://mrrorwallet.netlify.app"
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

// ✅ JSON body parser
app.use(express.json());

// Security headers
app.use((req, res, next) => {
  // HTTPS enforcement
  if (req.header('x-forwarded-proto') !== 'https' && process.env.NODE_ENV === 'production') {
    res.redirect(`https://${req.header('host')}${req.url}`);
  } else {
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  }
});

// Database configuration with better error handling
let sequelize;
let User;
let dbInitialized = false;

function initializeDatabase() {
  try {
    if (!process.env.DATABASE_URL) {
      console.log("⚠️ No DATABASE_URL found - running in demo mode");
      console.log("💡 To enable database features, add DATABASE_URL to your Render environment variables");
      return null;
    }

    console.log("🔄 Initializing database connection...");

    sequelize = new Sequelize(process.env.DATABASE_URL, {
      dialect: 'postgres',
      protocol: 'postgres',
      logging: process.env.NODE_ENV === 'development' ? console.log : false,
      pool: {
        max: 5,
        min: 0,
        acquire: 30000,
        idle: 10000
      },
      retry: {
        max: 5,
        backoffBase: 1000,
        backoffExponent: 1.5
      },
      dialectOptions: {
        ssl: process.env.NODE_ENV === 'production' ? {
          require: true,
          rejectUnauthorized: false
        } : false
      }
    });

    // Define User model
    User = sequelize.define('User', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      username: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false,
        validate: {
          len: [3, 50],
          isAlphanumeric: true
        }
      },
      password_hash: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      keystore: {
        type: DataTypes.TEXT,
        allowNull: false
      }
    }, {
      tableName: 'users',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    });

    return sequelize;
  } catch (err) {
    console.error("❌ Database initialization failed:", err.message);
    console.error("Full error:", err);
    return null;
  }
}


// Initialize database
(async () => {
  const db = initializeDatabase();

  if (!db) {
    console.log("⚠️ No database configured - running in demo mode");
    dbInitialized = false;
    return;
  }

  try {
    console.log("🔄 Attempting to connect to database...");
    await sequelize.authenticate();
    console.log("✅ PostgreSQL connection established");

    await sequelize.sync();
    console.log("✅ Database synchronized");
    dbInitialized = true;
  } catch (err) {
    console.error("❌ Database initialization failed:", err.message);
    console.error("❌ Full error:", err);
    console.log("⚠️ Server will start but database operations will fail");
    dbInitialized = false;
  }
})();
// Input validation middleware
function validateSignupInput(req, res, next) {
  const { username, password, keystore } = req.body;

  // Validate username
  if (!username || typeof username !== 'string' || username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: "Username must be 3-50 characters long" });
  }

  // Validate password
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters long" });
  }

  // Validate keystore
  if (!keystore || typeof keystore !== 'string' || keystore.length < 100) {
    return res.status(400).json({ error: "Invalid keystore data" });
  }

  // Check for common weak passwords
  const weakPasswords = ['password', '12345678', 'qwerty123', 'admin123', 'password123'];
  if (weakPasswords.includes(password.toLowerCase())) {
    return res.status(400).json({ error: "Password is too weak. Please choose a stronger password." });
  }

  next();
}

// Rate limiting (simple in-memory implementation)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_REQUESTS = 5; // 5 requests per window

function rateLimit(req, res, next) {
  const clientIP = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  // Get or create rate limit data for this IP
  if (!rateLimitMap.has(clientIP)) {
    rateLimitMap.set(clientIP, []);
  }

  const requests = rateLimitMap.get(clientIP);

  // Remove old requests outside the window
  while (requests.length > 0 && requests[0] < windowStart) {
    requests.shift();
  }

  // Check if rate limit exceeded
  if (requests.length >= RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).json({
      error: "Too many requests. Please try again later.",
      retryAfter: Math.ceil(RATE_LIMIT_WINDOW / 1000)
    });
  }

  // Add current request
  requests.push(now);
  next();
}

// Signup endpoint
app.post("/signup", rateLimit, validateSignupInput, async (req, res) => {
  if (!User) {
    return res.status(503).json({ error: "Database not configured. Please contact administrator." });
  }

  if (!dbInitialized) {
    return res.status(503).json({ error: "Database not ready. Please try again later." });
  }

  try {
    const { username, password, keystore } = req.body;

    // Additional server-side validation
    if (username.includes(' ')) {
      return res.status(400).json({ error: "Username cannot contain spaces" });
    }

    // Check if user exists
    const existingUser = await User.findOne({ where: { username } });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hash = await bcrypt.hash(password, 12);

    const newUser = await User.create({
      username,
      password_hash: hash,
      keystore
    });

    res.status(201).json({ message: "User created successfully", userId: newUser.id });
  } catch (err) {
    console.error("❌ Signup error:", err.message);
    if (err.name === 'SequelizeUniqueConstraintError') {
      res.status(409).json({ error: "Username already taken" });
    } else {
      res.status(500).json({ error: "Server error during signup. Please try again." });
    }
  }
});

// Input validation middleware for login
function validateLoginInput(req, res, next) {
  const { username, password } = req.body;

  if (!username || typeof username !== 'string' || username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: "Invalid username format" });
  }

  if (!password || typeof password !== 'string' || password.length < 1) {
    return res.status(400).json({ error: "Password is required" });
  }

  next();
}

// Login endpoint
app.post("/login", rateLimit, validateLoginInput, async (req, res) => {
  if (!User) {
    return res.status(503).json({ error: "Database not configured. Please contact administrator." });
  }

  if (!dbInitialized) {
    return res.status(503).json({ error: "Database not ready. Please try again later." });
  }

  try {
    const { username, password } = req.body;

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
  if (!User) {
    return res.status(503).json({ error: "Database not configured. Please contact administrator." });
  }

  if (!dbInitialized) {
    return res.status(503).json({ error: "Database not ready. Please try again later." });
  }

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

// Input validation middleware for keystore operations
function validateKeystoreInput(req, res, next) {
  const { username, password } = req.body;

  if (!username || typeof username !== 'string' || username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: "Invalid username format" });
  }

  if (!password || typeof password !== 'string' || password.length < 1) {
    return res.status(400).json({ error: "Password is required" });
  }

  next();
}

// Get keystore endpoint
app.post("/get-keystore", rateLimit, validateKeystoreInput, async (req, res) => {
  if (!User) {
    return res.status(503).json({ error: "Database not configured. Please contact administrator." });
  }

  if (!dbInitialized) {
    return res.status(503).json({ error: "Database not ready. Please try again later." });
  }

  try {
    const { username, password } = req.body;

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

// User profile endpoint (for data recovery)
app.get("/user/:userId", rateLimit, async (req, res) => {
  if (!User) {
    return res.status(503).json({ error: "Database not configured. Please contact administrator." });
  }

  if (!dbInitialized) {
    return res.status(503).json({ error: "Database not ready. Please try again later." });
  }

  try {
    const { userId } = req.params;

    if (!userId || isNaN(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Return non-sensitive user data
    res.json({
      userId: user.id,
      username: user.username,
      createdAt: user.created_at,
      accountExists: true
    });
  } catch (err) {
    console.error("❌ User lookup error:", err.message);
    res.status(500).json({ error: "Server error during user lookup." });
  }
});

// Backup endpoint (admin only - for data recovery)
app.get("/admin/backup", rateLimit, async (req, res) => {
  if (!User) {
    return res.status(503).json({ error: "Database not configured. Please contact administrator." });
  }

  if (!dbInitialized) {
    return res.status(503).json({ error: "Database not ready. Please try again later." });
  }

  // In production, add admin authentication here
  if (process.env.NODE_ENV === 'production' && req.headers.authorization !== 'Bearer ' + process.env.ADMIN_TOKEN) {
    return res.status(403).json({ error: "Admin access required" });
  }

  try {
    const users = await User.findAll({
      attributes: ['id', 'username', 'created_at', 'updated_at'],
      order: [['created_at', 'DESC']]
    });

    res.json({
      backup: {
        timestamp: new Date().toISOString(),
        totalUsers: users.length,
        users: users
      }
    });
  } catch (err) {
    console.error("❌ Backup error:", err.message);
    res.status(500).json({ error: "Server error during backup." });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  const health = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    database: dbInitialized ? 'connected' : 'disconnected',
    uptime: process.uptime()
  };

  const statusCode = dbInitialized ? 200 : 503;
  res.status(statusCode).json(health);
});

// API status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    message: 'Wallet API is running',
    version: '1.0.0',
    database: dbInitialized ? 'available' : 'unavailable',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    endpoints: [
      'POST /signup',
      'POST /login',
      'POST /import',
      'POST /get-keystore',
      'GET /user/:userId',
      'GET /admin/backup',
      'GET /health',
      'GET /api/status'
    ],
    security: {
      rateLimiting: 'enabled',
      inputValidation: 'enabled',
      cors: 'configured',
      httpsEnforcement: process.env.NODE_ENV === 'production' ? 'enabled' : 'disabled'
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `Route ${req.method} ${req.path} does not exist`
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Health check available at: http://localhost:${PORT}/health`);
  console.log(`📊 API status available at: http://localhost:${PORT}/api/status`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️ Database: ${dbInitialized ? '✅ Connected' : '❌ Disconnected'}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log("✅ Shutting down gracefully...");
  if (sequelize) {
    await sequelize.close();
    console.log("✅ Database connection closed");
  }
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log("✅ Received SIGTERM, shutting down gracefully...");
  if (sequelize) {
    await sequelize.close();
    console.log("✅ Database connection closed");
  }
  process.exit(0);
});
