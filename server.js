const crypto = require("crypto");
const express = require("express");
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

const NGN_FLAT_FEE_KOBO = 3000; // ₦30.00
const CRYPTO_FEE_RATE = 0.018; // 1.8%
const MAX_PASSCODE_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

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

function calculateFees({ channel, amountMinor, gasFeeMinor = 0 }) {
  if (channel === "NGN") {
    return {
      platformFeeMinor: NGN_FLAT_FEE_KOBO,
      gasFeeMinor: 0,
      totalDebitMinor: amountMinor + NGN_FLAT_FEE_KOBO
    };
  }
  if (channel === "CRYPTO") {
    const platformFeeMinor = Math.round(amountMinor * CRYPTO_FEE_RATE);
    const gas = Math.max(0, Number(gasFeeMinor) || 0);
    return {
      platformFeeMinor,
      gasFeeMinor: gas,
      totalDebitMinor: amountMinor + platformFeeMinor + gas
    };
  }
  throw new Error("Unsupported channel. Expected NGN or CRYPTO.");
}

app.get("/health", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS now");
    res.json({ ok: true, service: "nikofy-backend", dbTime: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
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
       WHERE id = $2
       RETURNING id, account_status`,
      [hashed, userId]
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
       FROM users WHERE id = $1`,
      [userId]
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
        [nextAttempts, lockUntil, userId]
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
      [userId]
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
      `SELECT id, account_status FROM users WHERE id = $1 FOR UPDATE`,
      [userId]
    );
    if (!userRes.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found." });
    }

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
      [userId]
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
        [userId]
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
      [userId]
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

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Nikofy backend listening on port ${port}`);
});
              
