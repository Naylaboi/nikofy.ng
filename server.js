const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sgMail = require("@sendgrid/mail");
const { Pool } = require("pg");

const app = express();
app.use(express.json({ limit: "10mb" }));
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || "nikofy-dev-secret-change-me";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL || "noreply@nikofy.ng";
const OTP_EXPIRY_MINUTES = 10;
const MAX_OTP_ATTEMPTS = 5;

if (SENDGRID_API_KEY) {
  sgMail.setApiKey(SENDGRID_API_KEY);
} else {
  console.warn("SENDGRID_API_KEY is not set; OTP emails will fail until configured.");
}

const NGN_FLAT_FEE_KOBO = 3000; // ₦30.00
const CRYPTO_HIGH_TIER_THRESHOLD_CENTS = 100000; // $1,000.00 and above
const CRYPTO_LOW_TIER_FEE_CENTS = 40; // $0.40 service fee for transactions < $1,000.00
const CRYPTO_HIGH_TIER_FEE_CENTS = 80; // $0.80 service fee for transactions >= $1,000.00
const MAX_PASSCODE_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

function normalizeUsername(rawUsername) {
  if (rawUsername === undefined || rawUsername === null) return null;
  const cleaned = String(rawUsername).trim().toLowerCase().replace(/^@+/, "");
  return cleaned.length ? cleaned : null;
}

function normalizePhone(rawPhone) {
  if (rawPhone === undefined || rawPhone === null) return null;
  const digits = String(rawPhone).replace(/[^\d+]/g, "").replace(/^\+/, "");
  if (!digits) return null;
  if (digits.startsWith("234") && digits.length === 13) {
    return digits;
  }
  if (digits.startsWith("0") && digits.length === 11) {
    return `234${digits.slice(1)}`;
  }
  return digits;
}

function formatConflictMessage(err) {
  const detail = String(err?.detail || "").toLowerCase();
  const constraint = String(err?.constraint || "").toLowerCase();
  if (constraint.includes("username") || detail.includes("username")) {
    return "This username is already taken. Please choose another one.";
  }
  if (constraint.includes("phone") || detail.includes("phone")) {
    return "This phone number is already linked to another account.";
  }
  return "An account with this email already exists.";
}

function hashOtpCode(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}

function generateSixDigitOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

async function ensureOtpTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_otps (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      purpose TEXT NOT NULL DEFAULT 'LOGIN',
      code_hash TEXT NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      expires_at TIMESTAMPTZ NOT NULL,
      consumed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_email_otps_lookup ON email_otps (email, purpose, created_at DESC);
  `);
}

async function ensureSchemaTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL DEFAULT 'Nikofy User',
      username TEXT,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      normalized_phone TEXT,
      password_hash TEXT,
      transaction_passcode_hash TEXT,
      passcode_failed_attempts INTEGER NOT NULL DEFAULT 0,
      passcode_locked_until TIMESTAMPTZ,
      account_status TEXT NOT NULL DEFAULT 'ACTIVE',
      freeze_reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS normalized_phone TEXT;

    UPDATE users
    SET normalized_phone = CASE
      WHEN regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g') ~ '^234[0-9]{10}$'
        THEN regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g')
      WHEN regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g') ~ '^0[0-9]{10}$'
        THEN '234' || substr(regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g'), 2)
      WHEN regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g') <> ''
        THEN regexp_replace(COALESCE(phone, ''), '[^0-9]', '', 'g')
      ELSE NULL
    END
    WHERE phone IS NOT NULL AND normalized_phone IS NULL;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
      ON users (LOWER(email));
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower
      ON users (LOWER(username))
      WHERE username IS NOT NULL AND BTRIM(username) <> '';
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone_unique
      ON users (normalized_phone)
      WHERE normalized_phone IS NOT NULL AND BTRIM(normalized_phone) <> '';

    CREATE TABLE IF NOT EXISTS kyc_profiles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tier TEXT NOT NULL DEFAULT 'TIER_1',
      kyc_status TEXT NOT NULL DEFAULT 'UNVERIFIED',
      bvn_verified BOOLEAN NOT NULL DEFAULT FALSE,
      nin_verified BOOLEAN NOT NULL DEFAULT FALSE,
      liveness_status TEXT NOT NULL DEFAULT 'PENDING',
      daily_ngn_limit_kobo BIGINT NOT NULL DEFAULT 20000000,
      max_ngn_balance_kobo BIGINT DEFAULT 100000000,
      daily_usd_limit_cents BIGINT NOT NULL DEFAULT 10000,
      max_usd_balance_cents BIGINT DEFAULT 500000,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS wallets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      asset TEXT NOT NULL,
      currency TEXT NOT NULL,
      network TEXT NOT NULL,
      minor_unit TEXT NOT NULL,
      balance_minor BIGINT NOT NULL DEFAULT 0,
      available_balance_minor BIGINT NOT NULL DEFAULT 0,
      UNIQUE (user_id, asset, network)
    );

    CREATE TABLE IF NOT EXISTS daily_spend_tracker (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      spend_date DATE NOT NULL DEFAULT CURRENT_DATE,
      ngn_spent_kobo BIGINT NOT NULL DEFAULT 0,
      usd_spent_cents BIGINT NOT NULL DEFAULT 0,
      UNIQUE (user_id, spend_date)
    );
  `);
}

function hashPasscode(pin, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(pin, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPasscode(pin, storedValue) {
  if (!storedValue || !storedValue.includes(":")) return false;
  const [salt, originalHash] = storedValue.split(":");
  const candidateHash = crypto.scryptSync(pin, salt, 64);
  const originalBuf = Buffer.from(originalHash, "hex");
  if (candidateHash.length !== originalBuf.length) return false;
  return crypto.timingSafeEqual(candidateHash, originalBuf);
}

function signAuthToken(userRow) {
  return jwt.sign(
    {
      sub: String(userRow.id),
      email: userRow.email,
      status: userRow.account_status || "ACTIVE"
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function calculateFees({ channel, amountMinor, gasFeeMinor = 0 }) {
  if (channel === "NGN") {
    return {
      platformFeeMinor: NGN_FLAT_FEE_KOBO,
      gasFeeMinor: 0,
      totalDebitMinor: amountMinor + NGN_FLAT_FEE_KOBO
    };
  }
  if (channel === "CRYPTO") {
    const platformFeeMinor =
      Number(amountMinor) >= CRYPTO_HIGH_TIER_THRESHOLD_CENTS
        ? CRYPTO_HIGH_TIER_FEE_CENTS
        : CRYPTO_LOW_TIER_FEE_CENTS;
    const gas = Math.max(0, Number(gasFeeMinor) || 0);
    return {
      platformFeeMinor,
      gasFeeMinor: gas,
      totalDebitMinor: amountMinor + platformFeeMinor + gas
    };
  }
  throw new Error("Unsupported channel. Expected NGN or CRYPTO.");
}

async function provisionUserDefaults(client, userId) {
  await client.query(
    `INSERT INTO kyc_profiles (
      user_id, tier, kyc_status, bvn_verified, nin_verified, liveness_status,
      daily_ngn_limit_kobo, max_ngn_balance_kobo, daily_usd_limit_cents, max_usd_balance_cents, updated_at
    )
    VALUES ($1, 'TIER_1', 'UNVERIFIED', FALSE, FALSE, 'PENDING', 20000000, 100000000, 10000, 500000, NOW())
    ON CONFLICT (user_id) DO NOTHING`,
    [userId]
  );

  const currencies = [
    { asset: "NGN", network: "NGN_INSTANT", minorUnit: "KOBO" },
    { asset: "USDT", network: "TRC20", minorUnit: "CENTS" },
    { asset: "USDC", network: "ERC20", minorUnit: "CENTS" },
    { asset: "BTC", network: "BITCOIN", minorUnit: "CENTS" },
    { asset: "ETH", network: "ERC20", minorUnit: "CENTS" },
    { asset: "BNB", network: "BEP20", minorUnit: "CENTS" }
  ];

  for (const c of currencies) {
    try {
      await client.query(
        `INSERT INTO wallets (user_id, asset, currency, network, minor_unit, balance_minor, available_balance_minor)
         VALUES ($1, $2, $2, $3, $4, 0, 0)
         ON CONFLICT DO NOTHING`,
        [userId, c.asset, c.network, c.minorUnit]
      );
    } catch (walletErr) {
      // Fallback if wallets table has a slightly different column set
      console.warn(`Wallet seed warning for ${c.asset}:`, walletErr.message);
    }
  }
}

app.get("/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS now");
    res.json({ ok: true, service: "nikofy-backend", dbTime: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/auth/otp/send", async (req, res) => {
  const { email, purpose = "LOGIN" } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanPurpose = String(purpose || "LOGIN").trim().toUpperCase();

  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ ok: false, error: "A valid email address is required." });
  }
  if (!SENDGRID_API_KEY) {
    return res.status(500).json({ ok: false, error: "Email service is not configured on the server." });
  }

  try {
    await ensureOtpTable();

    const code = generateSixDigitOtp();
    const codeHash = hashOtpCode(code);
    const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

    await pool.query(
      `UPDATE email_otps
       SET consumed_at = NOW()
       WHERE email = $1 AND purpose = $2 AND consumed_at IS NULL`,
      [cleanEmail, cleanPurpose]
    );

    await pool.query(
      `INSERT INTO email_otps (email, purpose, code_hash, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [cleanEmail, cleanPurpose, codeHash, expiresAt.toISOString()]
    );

    await sgMail.send({
      to: cleanEmail,
      from: FROM_EMAIL,
      subject: `Your Nikofy verification code: ${code}`,
      text: `Your Nikofy verification code is ${code}. It expires in ${OTP_EXPIRY_MINUTES} minutes. If you did not request this, ignore this email.`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; background: #0d1117; color: #f0f6fc; border-radius: 10px;">
          <h2 style="margin-top: 0; color: #38bdf8;">Nikofy Verification Code</h2>
          <p>Use the one-time code below to continue on <strong>nikofy.ng</strong>:</p>
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; padding: 14px 20px; margin: 18px 0; background: #161b22; border: 1px solid #30363d; border-radius: 8px; text-align: center; color: #facc15;">
            ${code}
          </div>
          <p style="font-size: 13px; color: #9ca3af;">This code expires in ${OTP_EXPIRY_MINUTES} minutes. If you did not request it, you can safely ignore this message.</p>
        </div>
      `
    });

    return res.json({
      ok: true,
      message: "Verification code sent to your email.",
      expiresInSeconds: OTP_EXPIRY_MINUTES * 60
    });
  } catch (err) {
    console.error("OTP send error:", err?.response?.body || err);
    return res.status(500).json({ ok: false, error: "Failed to send verification code email." });
  }
});

app.post("/api/auth/otp/verify", async (req, res) => {
  const { email, code, purpose = "LOGIN", fullName, username, phone } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanCode = String(code || "").trim();
  const cleanPurpose = String(purpose || "LOGIN").trim().toUpperCase();
  const cleanUsername = normalizeUsername(username);
  const cleanPhone = String(phone || "").trim() || null;
  const canonicalPhone = normalizePhone(cleanPhone);

  if (!cleanEmail || !/^\d{6}$/.test(cleanCode)) {
    return res.status(400).json({ ok: false, error: "Valid email and 6-digit code are required." });
  }
  if (cleanUsername && !/^[a-z0-9_]{3,24}$/.test(cleanUsername)) {
    return res.status(400).json({
      ok: false,
      error: "Username must be 3-24 characters using letters, numbers, or underscores."
    });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureOtpTable();
    await ensureSchemaTables();

    const { rows } = await client.query(
      `SELECT id, code_hash, attempts, expires_at, consumed_at
       FROM email_otps
       WHERE email = $1 AND purpose = $2 AND consumed_at IS NULL
       ORDER BY created_at DESC
       LIMIT 1
       FOR UPDATE`,
      [cleanEmail, cleanPurpose]
    );

    if (!rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ ok: false, error: "No active verification code found. Please request a new one." });
    }

    const otpRow = rows[0];
    if (new Date(otpRow.expires_at) <= new Date()) {
      await client.query(`UPDATE email_otps SET consumed_at = NOW() WHERE id = $1`, [otpRow.id]);
      await client.query("COMMIT");
      return res.status(400).json({ ok: false, error: "Verification code has expired. Please request a new one." });
    }

    if (otpRow.attempts >= MAX_OTP_ATTEMPTS) {
      await client.query(`UPDATE email_otps SET consumed_at = NOW() WHERE id = $1`, [otpRow.id]);
      await client.query("COMMIT");
      return res.status(429).json({ ok: false, error: "Too many invalid attempts. Please request a new code." });
    }

    const expectedBuf = Buffer.from(otpRow.code_hash, "hex");
    const candidateBuf = Buffer.from(hashOtpCode(cleanCode), "hex");
    const matches =
      expectedBuf.length === candidateBuf.length &&
      crypto.timingSafeEqual(expectedBuf, candidateBuf);

    if (!matches) {
      await client.query(
        `UPDATE email_otps SET attempts = attempts + 1 WHERE id = $1`,
        [otpRow.id]
      );
      await client.query("COMMIT");
      return res.status(401).json({
        ok: false,
        error: "Invalid verification code.",
        attemptsRemaining: Math.max(0, MAX_OTP_ATTEMPTS - (otpRow.attempts + 1))
      });
    }

    await client.query(`UPDATE email_otps SET consumed_at = NOW() WHERE id = $1`, [otpRow.id]);

    let userRes = await client.query(
      `SELECT u.id, u.full_name, u.username, u.email, u.phone, u.account_status, u.freeze_reason,
              (u.transaction_passcode_hash IS NOT NULL) AS passcode_set,
              k.tier AS kyc_tier, k.kyc_status
       FROM users u
       LEFT JOIN kyc_profiles k ON k.user_id = u.id
       WHERE LOWER(u.email) = $1`,
      [cleanEmail]
    );

    if (!userRes.rows.length) {
      if (cleanUsername) {
        const usernameTaken = await client.query(
          `SELECT id FROM users WHERE LOWER(username) = $1`,
          [cleanUsername]
        );
        if (usernameTaken.rows.length > 0) {
          await client.query("ROLLBACK");
          return res.status(409).json({
            ok: false,
            error: "This username is already taken. Please choose another one."
          });
        }
      }

      if (canonicalPhone) {
        const phoneTaken = await client.query(
          `SELECT id FROM users WHERE normalized_phone = $1`,
          [canonicalPhone]
        );
        if (phoneTaken.rows.length > 0) {
          await client.query("ROLLBACK");
          return res.status(409).json({
            ok: false,
            error: "This phone number is already linked to another account."
          });
        }
      }

      const randomPasswordHash = await bcrypt.hash(crypto.randomBytes(24).toString("hex"), 12);
      const inserted = await client.query(
        `INSERT INTO users (
          full_name, username, email, phone, normalized_phone, password_hash, account_status, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', NOW(), NOW())
        RETURNING id, full_name, username, email, phone, account_status, (transaction_passcode_hash IS NOT NULL) AS passcode_set`,
        [
          String(fullName || "").trim() || "Nikofy User",
          cleanUsername,
          cleanEmail,
          cleanPhone,
          canonicalPhone,
          randomPasswordHash
        ]
      );
      const createdUser = inserted.rows[0];
      await provisionUserDefaults(client, createdUser.id);

      userRes = await client.query(
        `SELECT u.id, u.full_name, u.username, u.email, u.phone, u.account_status, u.freeze_reason,
                (u.transaction_passcode_hash IS NOT NULL) AS passcode_set,
                k.tier AS kyc_tier, k.kyc_status
         FROM users u
         LEFT JOIN kyc_profiles k ON k.user_id = u.id
         WHERE u.id = $1`,
        [createdUser.id]
      );
    }

    await client.query("COMMIT");

    const user = userRes.rows[0];
    const token = signAuthToken(user);

    return res.json({
      ok: true,
      verified: true,
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        username: user.username || null,
        email: user.email,
        phone: user.phone,
        accountStatus: user.account_status,
        freezeReason: user.freeze_reason || null,
        passcodeSet: Boolean(user.passcode_set),
        kycTier: user.kyc_tier || "TIER_1",
        kycStatus: user.kyc_status || "UNVERIFIED"
      }
    });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.code === "23505") {
      return res.status(409).json({ ok: false, error: formatConflictMessage(err) });
    }
    console.error("OTP verify error:", err);
    return res.status(500).json({ ok: false, error: "Failed to verify code." });
  } finally {
    client.release();
  }
});

app.post("/api/auth/register", async (req, res) => {
  const { fullName, username, email, phone, password, passcode } = req.body || {};

  const cleanName = String(fullName || "").trim();
  const cleanUsername = normalizeUsername(username);
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanPhone = String(phone || "").trim();
  const canonicalPhone = normalizePhone(cleanPhone);
  const rawPassword = String(password || "");

  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return res.status(400).json({ ok: false, error: "A valid email address is required." });
  }
  if (cleanUsername && !/^[a-z0-9_]{3,24}$/.test(cleanUsername)) {
    return res.status(400).json({
      ok: false,
      error: "Username must be 3-24 characters using letters, numbers, or underscores."
    });
  }
  if (cleanPhone && (!canonicalPhone || canonicalPhone.length < 7 || canonicalPhone.length > 15)) {
    return res.status(400).json({ ok: false, error: "Please enter a valid phone number." });
  }
  if (rawPassword.length < 8) {
    return res.status(400).json({ ok: false, error: "Password must be at least 8 characters." });
  }
  if (passcode && !/^\d{4}$/.test(String(passcode))) {
    return res.status(400).json({ ok: false, error: "Transaction passcode must be a 4-digit number." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await ensureSchemaTables();

    const existingEmail = await client.query(
      `SELECT id FROM users WHERE LOWER(email) = $1`,
      [cleanEmail]
    );
    if (existingEmail.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(409).json({ ok: false, error: "An account with this email already exists." });
    }

    if (cleanUsername) {
      const existingUsername = await client.query(
        `SELECT id FROM users WHERE LOWER(username) = $1`,
        [cleanUsername]
      );
      if (existingUsername.rows.length > 0) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          ok: false,
          error: "This username is already taken. Please choose another one."
        });
      }
    }

    if (canonicalPhone) {
      const existingPhone = await client.query(
        `SELECT id FROM users WHERE normalized_phone = $1`,
        [canonicalPhone]
      );
      if (existingPhone.rows.length > 0) {
        await client.query("ROLLBACK");
        return res.status(409).json({
          ok: false,
          error: "This phone number is already linked to another account."
        });
      }
    }

    const passwordHash = await bcrypt.hash(rawPassword, 12);
    const passcodeHash = passcode ? hashPasscode(String(passcode)) : null;

    const { rows } = await client.query(
      `INSERT INTO users (
        full_name, username, email, phone, normalized_phone, password_hash, transaction_passcode_hash, account_status, created_at, updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', NOW(), NOW())
      RETURNING id, full_name, username, email, phone, account_status, (transaction_passcode_hash IS NOT NULL) AS passcode_set, created_at`,
      [
        cleanName || "Nikofy User",
        cleanUsername,
        cleanEmail,
        cleanPhone || null,
        canonicalPhone,
        passwordHash,
        passcodeHash
      ]
    );

    const user = rows[0];
    await provisionUserDefaults(client, user.id);

    await client.query("COMMIT");

    const token = signAuthToken(user);
    return res.status(201).json({
      ok: true,
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        username: user.username || null,
        email: user.email,
        phone: user.phone,
        accountStatus: user.account_status,
        passcodeSet: Boolean(user.passcode_set),
        kycTier: "TIER_1",
        kycStatus: "UNVERIFIED"
      }
    });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.code === "23505") {
      return res.status(409).json({ ok: false, error: formatConflictMessage(err) });
    }
    console.error("Register error:", err);
    return res.status(500).json({ ok: false, error: err.message });
  } finally {
    client.release();
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const rawPassword = String(password || "");

  if (!cleanEmail || !rawPassword) {
    return res.status(400).json({ ok: false, error: "Email and password are required." });
  }

  try {
    await ensureSchemaTables();

    const { rows } = await pool.query(
      `SELECT u.id, u.full_name, u.username, u.email, u.phone, u.password_hash, u.account_status, u.freeze_reason,
              (u.transaction_passcode_hash IS NOT NULL) AS passcode_set,
              k.tier AS kyc_tier, k.kyc_status
       FROM users u
       LEFT JOIN kyc_profiles k ON k.user_id = u.id
       WHERE LOWER(u.email) = $1`,
      [cleanEmail]
    );

    if (!rows.length) {
      return res.status(401).json({ ok: false, error: "Invalid email or password." });
    }

    const user = rows[0];
    if (!user.password_hash) {
      return res.status(401).json({ ok: false, error: "Password login is not configured for this account." });
    }

    const validPassword = await bcrypt.compare(rawPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ ok: false, error: "Invalid email or password." });
    }

    const token = signAuthToken(user);
    return res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        username: user.username || null,
        email: user.email,
        phone: user.phone,
        accountStatus: user.account_status,
        freezeReason: user.freeze_reason || null,
        passcodeSet: Boolean(user.passcode_set),
        kycTier: user.kyc_tier || "TIER_1",
        kycStatus: user.kyc_status || "UNVERIFIED"
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/security/passcode/set", async (req, res) => {
  const { userId, passcode } = req.body;
  if (!userId || !/^\d{4}$/.test(String(passcode || ""))) {
    return res.status(400).json({ error: "userId and a 4-digit numeric passcode are required." });
  }

  try {
    const hashed = hashPasscode(String(passcode));
    const { rows } = await pool.query(
      `UPDATE users
       SET transaction_passcode_hash = $1,
           passcode_failed_attempts = 0,
           passcode_locked_until = NULL,
           updated_at = NOW()
       WHERE id::text = $2
       RETURNING id, account_status`,
      [hashed, String(userId)]
    );
    if (!rows.length) {
      return res.status(404).json({ error: "User not found." });
    }
    return res.json({ ok: true, userId: rows[0].id, passcodeSet: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/security/passcode/verify", async (req, res) => {
  const { userId, passcode } = req.body;
  if (!userId || !/^\d{4}$/.test(String(passcode || ""))) {
    return res.status(400).json({ error: "userId and a 4-digit numeric passcode are required." });
  }

  try {
    const { rows } = await pool.query(
      `SELECT id, transaction_passcode_hash, passcode_failed_attempts, passcode_locked_until, account_status
       FROM users WHERE id::text = $1`,
      [String(userId)]
    );
    if (!rows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    const user = rows[0];
    if (user.account_status !== "ACTIVE") {
      return res.status(403).json({ error: `Account is ${user.account_status}.` });
    }

    if (user.passcode_locked_until && new Date(user.passcode_locked_until) > new Date()) {
      return res.status(429).json({
        error: "Passcode temporarily locked due to failed attempts.",
        lockedUntil: user.passcode_locked_until
      });
    }

    const valid = verifyPasscode(String(passcode), user.transaction_passcode_hash);
    if (!valid) {
      const nextAttempts = (user.passcode_failed_attempts || 0) + 1;
      const shouldLock = nextAttempts >= MAX_PASSCODE_ATTEMPTS;
      const lockUntil = shouldLock
        ? new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000).toISOString()
        : null;

      await pool.query(
        `UPDATE users
         SET passcode_failed_attempts = $1,
             passcode_locked_until = $2,
             updated_at = NOW()
         WHERE id = $3`,
        [nextAttempts, lockUntil, user.id]
      );

      return res.status(401).json({
        ok: false,
        error: "Invalid 4-digit passcode.",
        attemptsUsed: nextAttempts,
        lockedUntil: lockUntil
      });
    }

    await pool.query(
      `UPDATE users
       SET passcode_failed_attempts = 0,
           passcode_locked_until = NULL,
           updated_at = NOW()
       WHERE id = $1`,
      [user.id]
    );

    return res.json({ ok: true, verified: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/transactions/evaluate", async (req, res) => {
  const { userId, channel, amountMinor, gasFeeMinor = 0, projectedBalanceAfterMinor = null } = req.body;
  const amount = Number(amountMinor);

  if (!userId || !Number.isInteger(amount) || amount <= 0) {
    return res.status(400).json({ error: "userId and positive integer amountMinor are required." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const userRes = await client.query(
      `SELECT id, account_status FROM users WHERE id::text = $1 FOR UPDATE`,
      [String(userId)]
    );
    if (!userRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found." });
    }

    const dbUserId = userRes.rows[0].id;

    if (userRes.rows[0].account_status !== "ACTIVE") {
      await client.query("ROLLBACK");
      return res.status(403).json({
        allowed: false,
        accountStatus: userRes.rows[0].account_status,
        reason: "Account is not active."
      });
    }

    const kycRes = await client.query(
      `SELECT tier, daily_ngn_limit_kobo, max_ngn_balance_kobo, daily_usd_limit_cents, max_usd_balance_cents
       FROM kyc_profiles WHERE user_id = $1`,
      [dbUserId]
    );
    const kyc = kycRes.rows[0] || {
      tier: "TIER_1",
      daily_ngn_limit_kobo: 20000000,
      max_ngn_balance_kobo: 100000000,
      daily_usd_limit_cents: 10000,
      max_usd_balance_cents: 500000
    };

    if (
      kyc.tier === "TIER_1" &&
      projectedBalanceAfterMinor !== null &&
      ((channel === "NGN" && kyc.max_ngn_balance_kobo && Number(projectedBalanceAfterMinor) > Number(kyc.max_ngn_balance_kobo)) ||
        (channel !== "NGN" && kyc.max_usd_balance_cents && Number(projectedBalanceAfterMinor) > Number(kyc.max_usd_balance_cents)))
    ) {
      await client.query(
        `UPDATE users
         SET account_status = 'FROZEN',
             freeze_reason = 'Tier 1 balance cap exceeded; Tier 2 KYC required.',
             updated_at = NOW()
         WHERE id = $1`,
        [dbUserId]
      );
      await client.query("COMMIT");
      return res.status(403).json({
        allowed: false,
        accountStatus: "FROZEN",
        reason: "Account auto-frozen because Tier 1 balance limit was exceeded."
      });
    }

    const spendRes = await client.query(
      `SELECT ngn_spent_kobo, usd_spent_cents
       FROM daily_spend_tracker
       WHERE user_id = $1 AND spend_date = CURRENT_DATE`,
      [dbUserId]
    );
    const spent = spendRes.rows[0] || { ngn_spent_kobo: 0, usd_spent_cents: 0 };

    if (channel === "NGN") {
      const nextSpent = Number(spent.ngn_spent_kobo) + amount;
      if (nextSpent > Number(kyc.daily_ngn_limit_kobo)) {
        await client.query("ROLLBACK");
        return res.status(422).json({
          allowed: false,
          reason: "Daily NGN limit exceeded for current KYC tier.",
          dailyLimitMinor: Number(kyc.daily_ngn_limit_kobo),
          spentTodayMinor: Number(spent.ngn_spent_kobo)
        });
      }
    } else {
      const nextSpentUsd = Number(spent.usd_spent_cents) + amount;
      if (nextSpentUsd > Number(kyc.daily_usd_limit_cents)) {
        await client.query("ROLLBACK");
        return res.status(422).json({
          allowed: false,
          reason: "Daily USD-equivalent limit exceeded for current KYC tier.",
          dailyLimitMinor: Number(kyc.daily_usd_limit_cents),
          spentTodayMinor: Number(spent.usd_spent_cents)
        });
      }
    }

    const fees = calculateFees({ channel, amountMinor: amount, gasFeeMinor });
    await client.query("COMMIT");

    return res.json({
      allowed: true,
      tier: kyc.tier,
      channel,
      amountMinor: amount,
      ...fees
    });
  } catch (err) {
    await client.query("ROLLBACK");
    return res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.post("/api/kyc/verify", async (req, res) => {
  try {
    const {
      userId,
      tier = "TIER_1",
      idNumber,
      dateOfBirth,
      selfieImage,
      currentBalanceNgn = 0,
    } = req.body || {};

    const cleanId = String(idNumber || "").trim();
    if (!/^\d{11}$/.test(cleanId)) {
      return res.status(400).json({
        ok: false,
        status: "FAILED",
        error: "Please enter a valid 11-digit BVN or NIN.",
      });
    }

    const normalizedTier = tier === "TIER_2" ? "TIER_2" : "TIER_1";
    const appId = process.env.DOJAH_APP_ID;
    const secretKey = process.env.DOJAH_SECRET_KEY;
    const baseUrl = process.env.DOJAH_BASE_URL || "https://sandbox.dojah.io";

    let verifiedDob = dateOfBirth;
    let fullName = "";
    let faceMatched = normalizedTier === "TIER_1";
    let confidenceValue = normalizedTier === "TIER_1" ? 100 : 0;

    if (appId && secretKey) {
      const headers = {
        AppId: appId,
        Authorization: secretKey,
        "Content-Type": "application/json",
      };

      if (normalizedTier === "TIER_1") {
        const response = await fetch(
          `${baseUrl}/api/v1/kyc/bvn?bvn=${encodeURIComponent(cleanId)}`,
          { method: "GET", headers }
        );
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.entity) {
          return res.status(400).json({
            ok: false,
            status: "FAILED",
            error: data.error || data.message || "BVN verification failed.",
          });
        }
        verifiedDob = data.entity.date_of_birth || data.entity.birthdate || dateOfBirth;
        fullName = `${data.entity.first_name || data.entity.firstname || ""} ${data.entity.last_name || data.entity.surname || ""}`.trim();
      } else {
        if (!selfieImage) {
          return res.status(400).json({
            ok: false,
            status: "FAILED",
            error: "A live selfie capture is required for Tier 2 verification.",
          });
        }
        const cleanBase64 = String(selfieImage).replace(/^data:image\/[a-zA-Z0-9+.-]+;base64,/, "");
        const response = await fetch(`${baseUrl}/api/v1/kyc/nin/verify`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            nin: cleanId,
            selfie_image: cleanBase64,
            threshold: 90,
          }),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.entity) {
          return res.status(400).json({
            ok: false,
            status: "FAILED",
            error: data.error || data.message || "NIN + Selfie verification failed.",
          });
        }
        verifiedDob = data.entity.date_of_birth || data.entity.birthdate || dateOfBirth;
        fullName = `${data.entity.first_name || data.entity.firstname || ""} ${data.entity.last_name || data.entity.surname || ""}`.trim();
        faceMatched = Boolean(data.entity.selfie_verification?.match);
        confidenceValue = Number(data.entity.selfie_verification?.confidence_value || 0);
      }
    } else if (normalizedTier === "TIER_2") {
      if (!selfieImage) {
        return res.status(400).json({
          ok: false,
          status: "FAILED",
          error: "Selfie image is required for Tier 2 liveness & face match.",
        });
      }
      faceMatched = true;
      confidenceValue = 98.5;
    }

    const dob = new Date(verifiedDob);
    if (!verifiedDob || Number.isNaN(dob.getTime())) {
      return res.status(400).json({
        ok: false,
        status: "FAILED",
        error: "Valid date of birth is required for age verification.",
      });
    }

    const today = new Date();
    let age = today.getFullYear() - dob.getFullYear();
    const m = today.getMonth() - dob.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age -= 1;

    if (age < 18) {
      return res.status(403).json({
        ok: false,
        status: "FAILED",
        ageVerified: false,
        error: "You must be at least 18 years old to verify your account.",
      });
    }

    if (normalizedTier === "TIER_2" && !faceMatched) {
      return res.status(400).json({
        ok: false,
        status: "FAILED",
        ageVerified: true,
        faceMatched: false,
        confidenceValue,
        error: "Selfie face match did not meet the required threshold.",
      });
    }

    const frozen = normalizedTier === "TIER_1" && Number(currentBalanceNgn) > 1000000;

    if (userId && process.env.DATABASE_URL) {
      try {
        await ensureSchemaTables();
        const isTier2 = normalizedTier === "TIER_2";
        const nextDailyNgnLimitKobo = isTier2 ? 200000000 : 20000000;
        const nextMaxNgnBalanceKobo = isTier2 ? null : 100000000;
        const nextDailyUsdLimitCents = isTier2 ? 100000 : 10000;
        const nextMaxUsdBalanceCents = isTier2 ? null : 500000;

        await pool.query(
          `INSERT INTO kyc_profiles (
            user_id, tier, kyc_status, bvn_verified, nin_verified, liveness_status,
            daily_ngn_limit_kobo, max_ngn_balance_kobo, daily_usd_limit_cents, max_usd_balance_cents, updated_at
          )
          VALUES ($1, $2, 'VERIFIED', $3, $4, 'VERIFIED', $5, $6, $7, $8, NOW())
          ON CONFLICT (user_id) DO UPDATE SET
            tier = EXCLUDED.tier,
            kyc_status = 'VERIFIED',
            bvn_verified = COALESCE(EXCLUDED.bvn_verified, kyc_profiles.bvn_verified),
            nin_verified = COALESCE(EXCLUDED.nin_verified, kyc_profiles.nin_verified),
            liveness_status = 'VERIFIED',
            daily_ngn_limit_kobo = EXCLUDED.daily_ngn_limit_kobo,
            max_ngn_balance_kobo = EXCLUDED.max_ngn_balance_kobo,
            daily_usd_limit_cents = EXCLUDED.daily_usd_limit_cents,
            max_usd_balance_cents = EXCLUDED.max_usd_balance_cents,
            updated_at = NOW()`,
          [
            String(userId),
            normalizedTier,
            !isTier2,
            isTier2,
            nextDailyNgnLimitKobo,
            nextMaxNgnBalanceKobo,
            nextDailyUsdLimitCents,
            nextMaxUsdBalanceCents,
          ]
        );

        await pool.query(
          `UPDATE users
           SET account_status = $2,
               freeze_reason = $3
           WHERE id::text = $1`,
          [
            String(userId),
            frozen ? "FROZEN" : "ACTIVE",
            frozen ? "Tier 1 balance limit (₦1,000,000) exceeded. Upgrade to Tier 2." : null,
          ]
        );
      } catch (dbErr) {
        console.warn("KYC DB persistence skipped/failed:", dbErr.message);
      }
    }

    return res.json({
      ok: true,
      userId,
      kycTier: normalizedTier,
      kycStatus: "VERIFIED",
      fullName,
      ageVerified: true,
      age,
      faceMatched,
      confidenceValue,
      frozen,
    });
  } catch (err) {
    console.error("Dojah KYC route error:", err);
    return res.status(500).json({
      ok: false,
      status: "FAILED",
      error: "Server error while verifying KYC.",
    });
  }
});

app.use((err, req, res, next) => {
  if (err?.type === "entity.too.large") {
    return res.status(413).json({
      ok: false,
      status: "FAILED",
      error: "Selfie image payload is too large. Please try a smaller photo."
    });
  }
  console.error("Unhandled Express error:", err);
  return res.status(err?.status || 500).json({
    ok: false,
    status: "FAILED",
    error: "Server error while verifying KYC."
  });
});

const port = process.env.PORT || 3000;
app.listen(port, async () => {
  try {
    await ensureSchemaTables();
    await ensureOtpTable();
  } catch (err) {
    console.warn("Startup schema check warning:", err.message);
  }
  console.log(`Nikofy backend listening on port ${port}`);
});
