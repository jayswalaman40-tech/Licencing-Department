# LicenseShield

Production-grade SaaS platform for selling and managing **Chrome Extension licenses**, built for the Indian market (Razorpay payments, INR pricing).

Customers buy a license → receive a license key → activate it inside the extension. The extension then validates the license with the LicenseShield server on every launch, with anti-replay protection and offline-capable caching.

---

## Tech stack

| Layer       | Technology                                            |
| ----------- | ----------------------------------------------------- |
| Framework   | Next.js 15 (App Router), TypeScript (strict)          |
| UI          | TailwindCSS + shadcn/ui                               |
| Backend/DB  | Supabase (PostgreSQL + Auth + Edge Functions)         |
| Payments    | Razorpay (INR)                                        |
| Email       | Resend                                                |
| Auth/crypto | Supabase Auth, TOTP (otplib), JWT/HMAC (jose)         |

---

## Repository layout

```
.
├── apps/
│   └── web/                 # Next.js 15 application (dashboard, admin, public API)
│       ├── src/
│       │   ├── app/         # App Router routes
│       │   └── lib/         # Supabase clients, env validation, utils
│       ├── middleware.ts    # Auth protection for /dashboard and /admin
│       └── ...config
├── sdk/                     # @licenseshield/sdk — embed in the Chrome extension
├── supabase/
│   ├── config.toml          # Local Supabase stack configuration
│   └── migrations/          # Ordered SQL migrations (001 → 007)
├── .env.example             # All environment variables
└── package.json             # npm workspaces root
```

### Database migrations

| File                     | Purpose                                                            |
| ------------------------ | ----------------------------------------------------------------- |
| `001_extensions.sql`     | Enable pgcrypto, uuid-ossp, pg_trgm, pg_net                        |
| `002_tables.sql`         | All tables (users, licenses, devices, orders, payments, …)        |
| `003_indexes.sql`        | Indexes for hot query paths                                       |
| `004_functions.sql`      | License key generation, nonce/rate-limit, verify/activate RPCs    |
| `005_triggers.sql`       | `updated_at`, audit logs, auto order/ticket/invoice numbers       |
| `006_rls.sql`            | Row Level Security + `is_admin()` helper                          |
| `007_seed.sql`           | Demo product, three plans, `maintenance_mode` flag                |

---

## Prerequisites

- **Node.js** ≥ 20 and **npm** ≥ 10
- **Docker** (required by the Supabase local stack)
- **Supabase CLI** (installed as a dev dependency; or globally via `npm i -g supabase`)

---

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Configure environment

```bash
cp .env.example apps/web/.env.local
cp .env.example .env          # used by the root tooling / Supabase
```

Fill in the values. Generate the platform crypto material:

```bash
# HMAC secret used to sign/verify extension requests
openssl rand -hex 32          # → PLATFORM_SECRET_KEY

# RS256 keypair for offline license tokens
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem
# Paste the PEM contents into PLATFORM_RS256_PRIVATE_KEY / PLATFORM_RS256_PUBLIC_KEY
```

### 3. Start Supabase locally

```bash
npm run db:start        # supabase start
npm run db:reset        # applies all migrations + seed
```

After `db:start`, the CLI prints your local `API URL`, `anon key`, and
`service_role key` — copy them into `.env.local`.

> **Important:** the verification RPCs read the HMAC secret from a database
> setting. Configure it once so signatures validate:
>
> ```sql
> ALTER DATABASE postgres SET app.platform_secret_key = '<PLATFORM_SECRET_KEY>';
> ```
>
> (Run this against your local DB, and set the same on your hosted project.)

### 4. Generate database types (optional)

```bash
npm run db:types        # writes apps/web/src/lib/supabase/database.types.ts
```

### 5. Run the app

```bash
npm run dev             # http://localhost:3000
```

---

## The verification protocol

Every request from the extension is signed to prevent tampering and replay:

1. The SDK builds a canonical message:
   `license_key | fingerprint_hash | product_id | nonce | timestamp`
2. It computes `HMAC-SHA256(message, PLATFORM_SECRET_KEY)` (hex).
3. The server (`rpc_verify_license` / `rpc_activate_device`) re-validates:
   - timestamp within ±300 s,
   - nonce is single-use (`rpc_consume_nonce`),
   - signature matches,
   - rate limit (10/min per license key),
   - license status, device activation, and version requirements.

The matching client lives in [`sdk/`](./sdk) (`@licenseshield/sdk`).

```ts
import { LicenseShieldClient } from "@licenseshield/sdk";

const client = new LicenseShieldClient({
  baseUrl: "https://app.example.com",
  apiKey: "lsk_live_...",
  productId: "<product-uuid>",
  secret: "<PLATFORM_SECRET_KEY>",
  extensionVersion: chrome.runtime.getManifest().version,
});

await client.activate(licenseKey);
const result = await client.verify(licenseKey);
if (!result.valid) {
  /* lock the extension */
}
```

---

## Useful scripts

| Command              | Description                                  |
| -------------------- | -------------------------------------------- |
| `npm run dev`        | Start the Next.js dev server                 |
| `npm run build`      | Production build                             |
| `npm run lint`       | ESLint                                       |
| `npm run typecheck`  | TypeScript (no emit)                         |
| `npm run format`     | Prettier write                              |
| `npm run db:start`   | Start the local Supabase stack               |
| `npm run db:reset`   | Drop, re-create, and re-seed the local DB    |
| `npm run db:push`    | Push migrations to the linked remote project |
| `npm run db:types`   | Generate TypeScript types from the schema    |
| `npm run sdk:build`  | Build the client SDK                         |

---

## Security notes

- **Never** commit `.env*` files or `*.pem` keys (already in `.gitignore`).
- The `service_role` key and `SECURITY DEFINER` RPCs bypass RLS — keep them
  server-side only.
- RLS ensures customers can only read their own licenses, orders, payments,
  invoices, and tickets; admins (rows in the `admins` table) get full access via
  `is_admin()`.
