-- =============================================================================
-- 002_tables.sql
-- Core schema for LicenseShield. Tables are ordered to satisfy foreign-key
-- dependencies. All timestamps are timestamptz; monetary values are INR
-- numeric(10,2).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- users
-- Mirrors auth.users (1:1). `id` references the Supabase auth user so that
-- RLS policies can use auth.uid() = id directly.
-- -----------------------------------------------------------------------------
CREATE TABLE public.users (
  id            uuid PRIMARY KEY REFERENCES auth.users (id) ON DELETE CASCADE,
  email         text NOT NULL UNIQUE,
  full_name     text,
  phone         text,
  company_name  text,
  gst_number    text,
  address       jsonb,
  avatar_url    text,
  totp_enabled  boolean NOT NULL DEFAULT false,
  totp_secret   text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz
);

-- -----------------------------------------------------------------------------
-- admins
-- -----------------------------------------------------------------------------
CREATE TABLE public.admins (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL UNIQUE REFERENCES public.users (id) ON DELETE CASCADE,
  role          text NOT NULL CHECK (role IN ('super_admin', 'admin', 'support')),
  permissions   jsonb NOT NULL DEFAULT '{}'::jsonb,
  totp_enabled  boolean NOT NULL DEFAULT true,
  totp_secret   text,
  last_login_at timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- products
-- -----------------------------------------------------------------------------
CREATE TABLE public.products (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name               text NOT NULL,
  slug               text NOT NULL UNIQUE,
  description        text,
  features           jsonb NOT NULL DEFAULT '[]'::jsonb,
  is_active          boolean NOT NULL DEFAULT true,
  current_version    text,
  minimum_version    text,
  download_url       text,
  product_image_url  text,
  metadata           jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by         uuid REFERENCES public.admins (id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  deleted_at         timestamptz
);

-- -----------------------------------------------------------------------------
-- license_plans
-- -----------------------------------------------------------------------------
CREATE TABLE public.license_plans (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id          uuid NOT NULL REFERENCES public.products (id) ON DELETE CASCADE,
  name                text NOT NULL,
  plan_type           text NOT NULL CHECK (plan_type IN ('trial', 'monthly', 'quarterly', 'yearly', 'lifetime')),
  price_inr           numeric(10, 2) NOT NULL DEFAULT 0,
  original_price_inr  numeric(10, 2),
  device_limit        integer NOT NULL DEFAULT 1,
  duration_days       integer,
  trial_days          integer NOT NULL DEFAULT 0,
  razorpay_plan_id    text,
  features            jsonb NOT NULL DEFAULT '[]'::jsonb,
  is_active           boolean NOT NULL DEFAULT true,
  sort_order          integer NOT NULL DEFAULT 0,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- licenses
-- -----------------------------------------------------------------------------
CREATE TABLE public.licenses (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_key        text NOT NULL UNIQUE,
  user_id            uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  product_id         uuid NOT NULL REFERENCES public.products (id) ON DELETE RESTRICT,
  plan_id            uuid REFERENCES public.license_plans (id) ON DELETE SET NULL,
  status             text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'trial', 'active', 'expired', 'cancelled', 'revoked', 'disabled')),
  device_limit       integer NOT NULL,
  activations_count  integer NOT NULL DEFAULT 0,
  max_offline_hours  integer NOT NULL DEFAULT 72,
  issued_at          timestamptz,
  expires_at         timestamptz,
  trial_ends_at      timestamptz,
  last_verified_at   timestamptz,
  revoke_reason      text,
  metadata           jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- devices
-- -----------------------------------------------------------------------------
CREATE TABLE public.devices (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id       uuid NOT NULL REFERENCES public.licenses (id) ON DELETE CASCADE,
  user_id          uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  fingerprint_hash text NOT NULL,
  device_label     text,
  browser_info     jsonb,
  os_info          jsonb,
  timezone         text,
  is_active        boolean NOT NULL DEFAULT true,
  first_seen_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  deactivated_at   timestamptz,
  deactivated_by   text CHECK (deactivated_by IN ('user', 'admin', 'system')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  -- One physical device per license.
  CONSTRAINT devices_license_fingerprint_uniq UNIQUE (license_id, fingerprint_hash)
);

-- -----------------------------------------------------------------------------
-- activations
-- -----------------------------------------------------------------------------
CREATE TABLE public.activations (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id    uuid NOT NULL REFERENCES public.licenses (id) ON DELETE CASCADE,
  device_id     uuid REFERENCES public.devices (id) ON DELETE SET NULL,
  action        text NOT NULL CHECK (action IN ('activate', 'deactivate', 'verify', 'replace')),
  status        text NOT NULL CHECK (status IN ('success', 'failed', 'blocked')),
  ip_address    inet,
  user_agent    text,
  request_nonce text,
  error_code    text,
  metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- verification_logs
-- -----------------------------------------------------------------------------
CREATE TABLE public.verification_logs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id        uuid NOT NULL REFERENCES public.licenses (id) ON DELETE CASCADE,
  device_id         uuid REFERENCES public.devices (id) ON DELETE SET NULL,
  result            text NOT NULL CHECK (result IN ('valid', 'invalid', 'expired', 'revoked', 'offline_cache', 'rate_limited')),
  offline           boolean NOT NULL DEFAULT false,
  ip_address        inet,
  extension_version text,
  product_version   text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- coupons (declared before orders for the FK reference)
-- -----------------------------------------------------------------------------
CREATE TABLE public.coupons (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code                text NOT NULL UNIQUE,
  discount_type       text NOT NULL CHECK (discount_type IN ('percentage', 'fixed')),
  discount_value      numeric(10, 2) NOT NULL,
  max_uses            integer,
  used_count          integer NOT NULL DEFAULT 0,
  min_order_amount    numeric(10, 2) NOT NULL DEFAULT 0,
  applicable_products uuid[] NOT NULL DEFAULT '{}',
  applicable_plans    uuid[] NOT NULL DEFAULT '{}',
  valid_from          timestamptz,
  valid_until         timestamptz,
  is_active           boolean NOT NULL DEFAULT true,
  created_by          uuid REFERENCES public.admins (id) ON DELETE SET NULL,
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- orders
-- -----------------------------------------------------------------------------
CREATE TABLE public.orders (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_number      text NOT NULL UNIQUE,
  user_id           uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  product_id        uuid NOT NULL REFERENCES public.products (id) ON DELETE RESTRICT,
  plan_id           uuid NOT NULL REFERENCES public.license_plans (id) ON DELETE RESTRICT,
  coupon_id         uuid REFERENCES public.coupons (id) ON DELETE SET NULL,
  original_amount   numeric(10, 2) NOT NULL DEFAULT 0,
  discount_amount   numeric(10, 2) NOT NULL DEFAULT 0,
  final_amount      numeric(10, 2) NOT NULL,
  currency          text NOT NULL DEFAULT 'INR',
  status            text NOT NULL DEFAULT 'created'
                      CHECK (status IN ('created', 'paid', 'failed', 'refunded', 'cancelled')),
  razorpay_order_id text UNIQUE,
  notes             jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- payments
-- -----------------------------------------------------------------------------
CREATE TABLE public.payments (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id            uuid NOT NULL REFERENCES public.orders (id) ON DELETE CASCADE,
  user_id             uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  razorpay_payment_id text NOT NULL UNIQUE,
  razorpay_order_id   text,
  razorpay_signature  text,
  amount              numeric(10, 2) NOT NULL,
  currency            text NOT NULL DEFAULT 'INR',
  method              text,
  status              text NOT NULL DEFAULT 'created'
                        CHECK (status IN ('created', 'authorized', 'captured', 'failed', 'refunded')),
  captured_at         timestamptz,
  refunded_at         timestamptz,
  refund_amount       numeric(10, 2),
  idempotency_key     text NOT NULL UNIQUE,
  raw_response        jsonb,
  created_at          timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- subscriptions
-- -----------------------------------------------------------------------------
CREATE TABLE public.subscriptions (
  id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                  uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  license_id               uuid REFERENCES public.licenses (id) ON DELETE SET NULL,
  razorpay_subscription_id text UNIQUE,
  plan_id                  uuid REFERENCES public.license_plans (id) ON DELETE SET NULL,
  status                   text NOT NULL DEFAULT 'created'
                             CHECK (status IN ('created', 'authenticated', 'active', 'paused', 'cancelled', 'completed', 'expired')),
  current_start            timestamptz,
  current_end              timestamptz,
  next_billing_at          timestamptz,
  total_count              integer,
  paid_count               integer NOT NULL DEFAULT 0,
  remaining_count          integer,
  created_at               timestamptz NOT NULL DEFAULT now(),
  updated_at               timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- payment_logs (raw webhook events from Razorpay)
-- -----------------------------------------------------------------------------
CREATE TABLE public.payment_logs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  payment_id        uuid REFERENCES public.payments (id) ON DELETE SET NULL,
  order_id          uuid REFERENCES public.orders (id) ON DELETE SET NULL,
  event_type        text NOT NULL,
  razorpay_event_id text UNIQUE,
  payload           jsonb,
  processed         boolean NOT NULL DEFAULT false,
  processed_at      timestamptz,
  error             text,
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- api_keys (server-to-server keys used by extensions / integrations)
-- -----------------------------------------------------------------------------
CREATE TABLE public.api_keys (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                 text,
  key_hash             text NOT NULL UNIQUE,
  key_prefix           text NOT NULL,
  product_id           uuid REFERENCES public.products (id) ON DELETE CASCADE,
  scopes               text[] NOT NULL DEFAULT '{}',
  rate_limit_per_minute integer NOT NULL DEFAULT 60,
  last_used_at         timestamptz,
  expires_at           timestamptz,
  is_active            boolean NOT NULL DEFAULT true,
  created_by           uuid REFERENCES public.admins (id) ON DELETE SET NULL,
  created_at           timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- nonces (single-use anti-replay tokens)
-- -----------------------------------------------------------------------------
CREATE TABLE public.nonces (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce      text NOT NULL UNIQUE,
  used       boolean NOT NULL DEFAULT false,
  used_at    timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- rate_limits (sliding window counters)
-- -----------------------------------------------------------------------------
CREATE TABLE public.rate_limits (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier      text NOT NULL,
  identifier_type text NOT NULL CHECK (identifier_type IN ('license_key', 'ip', 'device')),
  endpoint        text NOT NULL,
  request_count   integer NOT NULL DEFAULT 1,
  window_start    timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT rate_limits_window_uniq UNIQUE (identifier, identifier_type, endpoint, window_start)
);

-- -----------------------------------------------------------------------------
-- feature_flags
-- -----------------------------------------------------------------------------
CREATE TABLE public.feature_flags (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key                text NOT NULL UNIQUE,
  value              jsonb NOT NULL,
  description        text,
  enabled            boolean NOT NULL DEFAULT false,
  rollout_percentage integer NOT NULL DEFAULT 0 CHECK (rollout_percentage BETWEEN 0 AND 100),
  updated_by         uuid REFERENCES public.admins (id) ON DELETE SET NULL,
  updated_at         timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- support_tickets
-- -----------------------------------------------------------------------------
CREATE TABLE public.support_tickets (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ticket_number text NOT NULL UNIQUE,
  user_id       uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  subject       text NOT NULL,
  status        text NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open', 'in_progress', 'waiting', 'resolved', 'closed')),
  priority      text NOT NULL DEFAULT 'medium'
                  CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  product_id    uuid REFERENCES public.products (id) ON DELETE SET NULL,
  license_id    uuid REFERENCES public.licenses (id) ON DELETE SET NULL,
  messages      jsonb NOT NULL DEFAULT '[]'::jsonb,
  assigned_to   uuid REFERENCES public.admins (id) ON DELETE SET NULL,
  resolved_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- email_logs
-- -----------------------------------------------------------------------------
CREATE TABLE public.email_logs (
  id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id   uuid REFERENCES public.users (id) ON DELETE SET NULL,
  template  text NOT NULL,
  to_email  text NOT NULL,
  subject   text NOT NULL,
  resend_id text,
  status    text NOT NULL DEFAULT 'queued'
              CHECK (status IN ('queued', 'sent', 'delivered', 'failed', 'bounced')),
  error     text,
  metadata  jsonb NOT NULL DEFAULT '{}'::jsonb,
  sent_at   timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- audit_logs
-- actor_id is an unconstrained uuid because actors may be users, admins,
-- system, or webhook — actor_type disambiguates.
-- -----------------------------------------------------------------------------
CREATE TABLE public.audit_logs (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id      uuid,
  actor_type    text NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'webhook')),
  action        text NOT NULL,
  resource_type text NOT NULL,
  resource_id   uuid,
  old_value     jsonb,
  new_value     jsonb,
  ip_address    inet,
  user_agent    text,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- notifications
-- -----------------------------------------------------------------------------
CREATE TABLE public.notifications (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  title      text NOT NULL,
  body       text NOT NULL,
  type       text NOT NULL DEFAULT 'info' CHECK (type IN ('info', 'success', 'warning', 'error')),
  read       boolean NOT NULL DEFAULT false,
  action_url text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- invoices
-- -----------------------------------------------------------------------------
CREATE TABLE public.invoices (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  invoice_number text NOT NULL UNIQUE,
  order_id       uuid NOT NULL REFERENCES public.orders (id) ON DELETE CASCADE,
  user_id        uuid NOT NULL REFERENCES public.users (id) ON DELETE CASCADE,
  line_items     jsonb NOT NULL,
  subtotal       numeric(10, 2),
  tax_amount     numeric(10, 2) NOT NULL DEFAULT 0,
  total          numeric(10, 2) NOT NULL,
  currency       text NOT NULL DEFAULT 'INR',
  pdf_url        text,
  created_at     timestamptz NOT NULL DEFAULT now()
);
