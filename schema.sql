-- 1. Users & Security Credentials
CREATE TABLE users (
  id UUID PRIMARY KEY,
  phone_e164 VARCHAR(20) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(40) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  transaction_passcode_hash TEXT, -- Set up before authorizing transactions
  two_fa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  two_fa_secret_encrypted TEXT,
  account_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, FROZEN, SUSPENDED
  freeze_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. KYC Tier & Verification Status (Tier 1: BVN + Liveness | Tier 2: NIN + Liveness)
CREATE TABLE kyc_profiles (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  tier VARCHAR(10) NOT NULL DEFAULT 'TIER_1', -- TIER_1, TIER_2
  kyc_status VARCHAR(20) NOT NULL DEFAULT 'UNVERIFIED', -- UNVERIFIED, IN_PROGRESS, VERIFIED
  bvn_verified BOOLEAN NOT NULL DEFAULT FALSE,
  nin_verified BOOLEAN NOT NULL DEFAULT FALSE,
  liveness_status VARCHAR(20) NOT NULL DEFAULT 'UNVERIFIED', -- UNVERIFIED, IN_PROGRESS, VERIFIED
  daily_ngn_limit_kobo BIGINT NOT NULL DEFAULT 20000000, -- ₦200,000.00 default Tier 1 (10x on Tier 2)
  max_ngn_balance_kobo BIGINT, -- 100000000 (₦1,000,000) for Tier 1; NULL for Tier 2 unlimited
  daily_usd_limit_cents BIGINT NOT NULL DEFAULT 10000, -- $100.00 default Tier 1 (10x on Tier 2)
  max_usd_balance_cents BIGINT, -- 500000 ($5,000) for Tier 1; NULL for Tier 2 unlimited
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Wallets / Sub-Ledgers (NGN in kobo, Crypto in smallest unit)
CREATE TABLE wallets (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  asset_code VARCHAR(20) NOT NULL, -- NGN, USDT, USDC, BTC, ETH, BNB
  available_minor BIGINT NOT NULL DEFAULT 0 CHECK (available_minor >= 0),
  locked_minor BIGINT NOT NULL DEFAULT 0 CHECK (locked_minor >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, asset_code)
);

-- 4. External Crypto Deposit Addresses
CREATE TABLE crypto_addresses (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  asset_code VARCHAR(20) NOT NULL, -- USDT, USDC, BTC, ETH, BNB
  network VARCHAR(20) NOT NULL, -- TRC20, BEP20, ERC20, BTC, BSC
  address VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Transactions & Itemized Fees (₦30 NGN / 1.8% + gas Crypto)
CREATE TABLE transactions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  idempotency_key VARCHAR(120) UNIQUE NOT NULL,
  tx_type VARCHAR(30) NOT NULL, -- NGN_DEPOSIT, NGN_WITHDRAWAL, BUY_CRYPTO, SELL_CRYPTO, CRYPTO_DEPOSIT, CRYPTO_WITHDRAWAL, P2P_SEND, BILL_PAYMENT
  asset_code VARCHAR(20) NOT NULL,
  amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
  platform_fee_minor BIGINT NOT NULL DEFAULT 0, -- e.g., 3000 kobo (₦30) or 1.8% crypto fee
  gas_fee_minor BIGINT NOT NULL DEFAULT 0,
  counterparty_ref VARCHAR(255), -- Recipient username, bank account, external address, or meter/phone
  status VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING, COMPLETED, FAILED, REVERSED
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. 6-Digit OTP Challenges (Sign-Up, Sign-In, Sensitive Actions)
CREATE TABLE otp_challenges (
  id UUID PRIMARY KEY,
  contact_value VARCHAR(255) NOT NULL, -- Email or E.164 phone
  channel VARCHAR(10) NOT NULL, -- EMAIL, PHONE
  purpose VARCHAR(20) NOT NULL, -- SIGNUP, LOGIN, RESET
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
