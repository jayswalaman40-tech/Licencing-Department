-- =============================================================================
-- 001_extensions.sql
-- Enable required PostgreSQL extensions.
-- =============================================================================

-- Cryptographic functions: gen_random_bytes(), digest(), hmac(), crypt().
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions;

-- UUID generation helpers (uuid_generate_v4, etc.).
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;

-- Trigram matching for fuzzy text search (emails, names, license keys).
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;

-- Async HTTP from within the database (webhooks, outbound calls).
CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
