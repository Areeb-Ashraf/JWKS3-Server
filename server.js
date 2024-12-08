const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const argon2 = require("argon2");
const sqlite3 = require("sqlite3").verbose();
const rateLimit = require("express-rate-limit");

const app = express();
const port = 8080;
app.use(express.json());

// Database setup
const db = new sqlite3.Database("secure_jwks.db", (err) => {
  if (err) {
    console.error("Error opening database:", err.message);
  } else {
    db.serialize(() => {
      db.run(
        `
        CREATE TABLE IF NOT EXISTS keys (
          kid TEXT PRIMARY KEY,
          key BLOB NOT NULL,
          exp INTEGER NOT NULL
        )
      `,
        (err) => {
          if (err) {
            console.error("Error creating keys table:", err.message);
          } else {
            console.log("Keys table created or already exists.");
          }
        }
      );

      db.run(
        `
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          email TEXT UNIQUE,
          date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          last_login TIMESTAMP
        )
      `,
        (err) => {
          if (err) {
            console.error("Error creating users table:", err.message);
          } else {
            console.log("Users table created or already exists.");
          }
        }
      );

      db.run(
        `
        CREATE TABLE IF NOT EXISTS auth_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          request_ip TEXT NOT NULL,
          request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          user_id INTEGER,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
      `,
        (err) => {
          if (err) {
            console.error("Error creating auth_logs table:", err.message);
          } else {
            console.log("Auth logs table created or already exists.");
          }
        }
      );
    });
  }
});

// AES encryption utilities
const AES_KEY =
  process.env.NOT_MY_KEY || crypto.randomBytes(32).toString("base64");
const IV_LENGTH = 16;

function encrypt(data) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(AES_KEY, "base64"),
    iv
  );
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    encryptedData: encrypted.toString("base64"),
  };
}

function decrypt(encrypted, iv) {
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(AES_KEY, "base64"),
    Buffer.from(iv, "base64")
  );
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString();
}

// Generate and encrypt key pairs
async function generateAndStoreKeys() {
  const now = Math.floor(Date.now() / 1000);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const privateKeyPEM = privateKey.export({ type: "pkcs1", format: "pem" });
  const { iv, encryptedData } = encrypt(privateKeyPEM);

  // Store valid key
  db.run(`INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)`, [
    uuidv4(),
    JSON.stringify({ iv, encryptedData }),
    now + 3600,
  ]);

  // Store expired key
  db.run(`INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)`, [
    uuidv4(),
    JSON.stringify({ iv, encryptedData }),
    now - 3600,
  ]);
}

// User registration endpoint
app.post("/register", async (req, res) => {
  const { username, email } = req.body;
  const password = uuidv4();

  try {
    const passwordHash = await argon2.hash(password);
    db.run(
      `INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`,
      [username, passwordHash, email],
      function (err) {
        if (err) {
          return res
            .status(400)
            .json({ error: "Username or email already exists." });
        }
        res.status(201).json({ password });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error registering user." });
  }
});

// Log authentication requests
function logAuthRequest(ip, userId) {
  db.run(
    `INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)`,
    [ip, new Date().toISOString(), userId || null],
    (err) => {
      if (err)
        console.error("Error logging authentication request:", err.message);
    }
  );
}

// Authentication endpoint
app.post("/auth", async (req, res) => {
  const ip = req.ip;

  try {
    const { username, password } = req.body;
    db.get(
      `SELECT id, password_hash FROM users WHERE username = ?`,
      [username],
      async (err, user) => {
        if (err || !user) {
          logAuthRequest(ip, null);
          return res.status(401).json({ error: "Invalid credentials." });
        }

        const isValidPassword = await argon2.verify(
          user.password_hash,
          password
        );
        logAuthRequest(ip, user.id);

        if (isValidPassword) {
          res.status(200).json({ message: "Authentication successful." });
        } else {
          res.status(401).json({ error: "Invalid credentials." });
        }
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error processing authentication request." });
  }
});

// Rate limiter middleware
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // Limit each IP to 10 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Import the rate limiter middleware
const authRateLimiter = rateLimit({
  windowMs: 1000, // 1 second
  max: 10, // Limit each IP to 10 requests per second
  handler: (req, res) => {
    res
      .status(429)
      .json({ error: "Too many requests. Please try again later." });
  },
  keyGenerator: (req) => req.ip, // Use IP as the key
  skipSuccessfulRequests: true, // Only count failed requests
});

// Apply the rate limiter middleware to the /auth endpoint
app.post("/auth", authRateLimiter, async (req, res) => {
  const ip = req.ip;

  try {
    const { username, password } = req.body;

    // Check for the user in the database
    db.get(
      `SELECT id, password_hash FROM users WHERE username = ?`,
      [username],
      async (err, user) => {
        if (err || !user) {
          // Log only failed attempts
          logAuthRequest(ip, null);
          return res.status(401).json({ error: "Invalid credentials." });
        }

        // Verify the password
        const isValidPassword = await argon2.verify(
          user.password_hash,
          password
        );

        if (isValidPassword) {
          // Log successful authentication
          logAuthRequest(ip, user.id);
          res.status(200).json({ message: "Authentication successful." });
        } else {
          // Log failed attempt
          logAuthRequest(ip, null);
          res.status(401).json({ error: "Invalid credentials." });
        }
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Error processing authentication request." });
  }
});

// Start the server
generateAndStoreKeys().then(() => {
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
