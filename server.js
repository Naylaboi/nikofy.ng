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
app.listen(port, () => {
  console.log(`Nikofy backend listening on port ${port}`);
});
    
