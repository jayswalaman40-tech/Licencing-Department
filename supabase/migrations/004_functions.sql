-- =============================================================================
-- 004_functions.sql
-- Business logic: triggers helpers, license key generation, anti-replay,
-- rate limiting, and the security-critical verify/activate RPCs.
--
-- HMAC signing secret is read from the database GUC `app.platform_secret_key`.
-- Set it once per environment, e.g.:
--   ALTER DATABASE postgres SET app.platform_secret_key = '<PLATFORM_SECRET_KEY>';
-- This must match PLATFORM_SECRET_KEY used by the app/SDK to sign requests.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- set_updated_at() — generic BEFORE UPDATE trigger to bump updated_at.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- -----------------------------------------------------------------------------
-- _platform_secret() — fetch the shared HMAC secret (NULL if unset).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._platform_secret()
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT current_setting('app.platform_secret_key', true);
$$;

-- -----------------------------------------------------------------------------
-- _verify_signature(message, signature)
-- Recompute HMAC-SHA256(message, secret) and compare (hex, case-insensitive).
-- Returns false if no secret is configured.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._verify_signature(p_message text, p_signature text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = public, extensions
AS $$
DECLARE
  v_secret   text := public._platform_secret();
  v_expected text;
BEGIN
  IF v_secret IS NULL OR v_secret = '' OR p_signature IS NULL THEN
    RETURN false;
  END IF;
  v_expected := encode(extensions.hmac(p_message, v_secret, 'sha256'), 'hex');
  RETURN lower(v_expected) = lower(p_signature);
END;
$$;

-- -----------------------------------------------------------------------------
-- _canonical_message(...) — deterministic string the SDK must reproduce.
-- Fields joined with '|'; missing optional fields become ''.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._canonical_message(
  p_license_key text,
  p_fingerprint_hash text,
  p_product_id uuid,
  p_nonce text,
  p_timestamp bigint
)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT concat_ws(
    '|',
    p_license_key,
    p_fingerprint_hash,
    coalesce(p_product_id::text, ''),
    p_nonce,
    p_timestamp::text
  );
$$;

-- -----------------------------------------------------------------------------
-- _version_lt(a, b) — true if semver-ish version a < b. Tolerant of nulls and
-- non-numeric segments.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._version_lt(a text, b text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  arr_a text[];
  arr_b text[];
  n     int;
  i     int;
  va    int;
  vb    int;
BEGIN
  IF a IS NULL OR b IS NULL THEN
    RETURN false;
  END IF;
  arr_a := string_to_array(a, '.');
  arr_b := string_to_array(b, '.');
  n := greatest(coalesce(array_length(arr_a, 1), 0), coalesce(array_length(arr_b, 1), 0));
  FOR i IN 1..n LOOP
    va := coalesce(nullif(regexp_replace(coalesce(arr_a[i], '0'), '[^0-9]', '', 'g'), '')::int, 0);
    vb := coalesce(nullif(regexp_replace(coalesce(arr_b[i], '0'), '[^0-9]', '', 'g'), '')::int, 0);
    IF va < vb THEN RETURN true; END IF;
    IF va > vb THEN RETURN false; END IF;
  END LOOP;
  RETURN false;
END;
$$;

-- -----------------------------------------------------------------------------
-- (b) rpc_generate_license_key() — XXXX-XXXX-XXXX-XXXX, no ambiguous chars.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_generate_license_key()
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_charset constant text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; -- 31 chars, no 0/O/1/I/L
  v_len     constant int := length('ABCDEFGHJKMNPQRSTUVWXYZ23456789');
  v_bytes   bytea;
  v_key     text;
  v_idx     int;
  i         int;
BEGIN
  LOOP
    v_key := '';
    v_bytes := extensions.gen_random_bytes(16);
    FOR i IN 0..15 LOOP
      v_idx := (get_byte(v_bytes, i) % v_len) + 1;
      v_key := v_key || substr(v_charset, v_idx, 1);
      IF i IN (3, 7, 11) THEN
        v_key := v_key || '-';
      END IF;
    END LOOP;
    EXIT WHEN NOT EXISTS (SELECT 1 FROM public.licenses WHERE license_key = v_key);
  END LOOP;
  RETURN v_key;
END;
$$;

-- -----------------------------------------------------------------------------
-- (c) rpc_consume_nonce(p_nonce) — single-use, atomic.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_consume_nonce(p_nonce text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_row public.nonces%ROWTYPE;
BEGIN
  IF p_nonce IS NULL OR p_nonce = '' THEN
    RETURN false;
  END IF;

  -- Fast path: claim a never-seen nonce in one atomic insert.
  INSERT INTO public.nonces (nonce, used, used_at, expires_at)
  VALUES (p_nonce, true, now(), now() + interval '10 minutes')
  ON CONFLICT (nonce) DO NOTHING;

  IF FOUND THEN
    RETURN true;
  END IF;

  -- Seen before: lock the row and decide.
  SELECT * INTO v_row FROM public.nonces WHERE nonce = p_nonce FOR UPDATE;

  IF NOT FOUND THEN
    RETURN false;
  END IF;
  IF v_row.used THEN
    RETURN false;            -- replay attempt
  END IF;
  IF v_row.expires_at < now() THEN
    RETURN false;            -- expired
  END IF;

  UPDATE public.nonces
     SET used = true, used_at = now()
   WHERE id = v_row.id;
  RETURN true;
END;
$$;

-- -----------------------------------------------------------------------------
-- (d) rpc_check_rate_limit(...) — fixed-window counter. TRUE = limit exceeded.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_check_rate_limit(
  p_identifier text,
  p_identifier_type text,
  p_endpoint text,
  p_max_requests int,
  p_window_seconds int
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_window_start timestamptz;
  v_count        int;
BEGIN
  v_window_start := to_timestamp(
    floor(extract(epoch FROM now()) / p_window_seconds) * p_window_seconds
  );

  INSERT INTO public.rate_limits (identifier, identifier_type, endpoint, request_count, window_start)
  VALUES (p_identifier, p_identifier_type, p_endpoint, 1, v_window_start)
  ON CONFLICT (identifier, identifier_type, endpoint, window_start)
  DO UPDATE SET request_count = public.rate_limits.request_count + 1
  RETURNING request_count INTO v_count;

  RETURN v_count > p_max_requests;
END;
$$;

-- -----------------------------------------------------------------------------
-- (e) rpc_verify_license(...) — full verification pipeline.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_verify_license(
  p_license_key text,
  p_fingerprint_hash text,
  p_product_id uuid,
  p_nonce text,
  p_timestamp bigint,
  p_signature text,
  p_api_key_hash text,
  p_extension_version text,
  p_ip inet
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_license       public.licenses%ROWTYPE;
  v_product       public.products%ROWTYPE;
  v_device        public.devices%ROWTYPE;
  v_message       text;
  v_update_req    boolean := false;
  v_remaining     int;
  v_result        text;
BEGIN
  -- 1. Timestamp freshness (±300s).
  IF p_timestamp IS NULL OR abs(extract(epoch FROM now())::bigint - p_timestamp) > 300 THEN
    RETURN jsonb_build_object('valid', false, 'status', 'invalid', 'error', 'stale_timestamp');
  END IF;

  -- 2. Anti-replay nonce.
  IF NOT public.rpc_consume_nonce(p_nonce) THEN
    RETURN jsonb_build_object('valid', false, 'status', 'invalid', 'error', 'replay_detected');
  END IF;

  -- 3. HMAC signature.
  v_message := public._canonical_message(p_license_key, p_fingerprint_hash, p_product_id, p_nonce, p_timestamp);
  IF NOT public._verify_signature(v_message, p_signature) THEN
    RETURN jsonb_build_object('valid', false, 'status', 'invalid', 'error', 'bad_signature');
  END IF;

  -- 3b. API key must be valid/active.
  IF p_api_key_hash IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.api_keys
      WHERE key_hash = p_api_key_hash
        AND is_active = true
        AND (expires_at IS NULL OR expires_at > now())
    ) THEN
      RETURN jsonb_build_object('valid', false, 'status', 'invalid', 'error', 'invalid_api_key');
    END IF;
    UPDATE public.api_keys SET last_used_at = now() WHERE key_hash = p_api_key_hash;
  END IF;

  -- 4. Rate limit: 10 requests / minute / license_key.
  IF public.rpc_check_rate_limit(p_license_key, 'license_key', 'verify', 10, 60) THEN
    INSERT INTO public.verification_logs (license_id, result, offline, ip_address, extension_version)
    SELECT id, 'rate_limited', false, p_ip, p_extension_version
      FROM public.licenses WHERE license_key = p_license_key;
    RETURN jsonb_build_object('valid', false, 'status', 'rate_limited', 'error', 'rate_limited');
  END IF;

  -- 5. Find license.
  SELECT * INTO v_license FROM public.licenses WHERE license_key = p_license_key;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('valid', false, 'status', 'invalid', 'error', 'license_not_found');
  END IF;

  -- Product match (when supplied).
  IF p_product_id IS NOT NULL AND v_license.product_id <> p_product_id THEN
    RETURN jsonb_build_object('valid', false, 'status', 'invalid', 'error', 'product_mismatch');
  END IF;

  SELECT * INTO v_product FROM public.products WHERE id = v_license.product_id;

  -- 6. Status checks (auto-expire if past expiry).
  IF v_license.expires_at IS NOT NULL AND v_license.expires_at < now()
     AND v_license.status IN ('active', 'trial') THEN
    UPDATE public.licenses SET status = 'expired' WHERE id = v_license.id;
    v_license.status := 'expired';
  END IF;

  IF v_license.status IN ('revoked', 'disabled', 'cancelled') THEN
    v_result := 'revoked';
  ELSIF v_license.status = 'expired' THEN
    v_result := 'expired';
  ELSIF v_license.status NOT IN ('active', 'trial') THEN
    v_result := 'invalid';
  ELSE
    v_result := 'valid';
  END IF;

  -- 7. Device must be activated and active.
  IF v_result = 'valid' THEN
    SELECT * INTO v_device
      FROM public.devices
     WHERE license_id = v_license.id
       AND fingerprint_hash = p_fingerprint_hash
       AND is_active = true;
    IF NOT FOUND THEN
      v_result := 'invalid';
    END IF;
  END IF;

  -- 8. Product version requirement.
  IF v_product.minimum_version IS NOT NULL
     AND public._version_lt(p_extension_version, v_product.minimum_version) THEN
    v_update_req := true;
  END IF;

  -- 9. Touch last_verified_at on success.
  IF v_result = 'valid' THEN
    UPDATE public.licenses SET last_verified_at = now() WHERE id = v_license.id;
    IF v_device.id IS NOT NULL THEN
      UPDATE public.devices SET last_seen_at = now() WHERE id = v_device.id;
    END IF;
  END IF;

  -- 10. Log verification.
  INSERT INTO public.verification_logs
    (license_id, device_id, result, offline, ip_address, extension_version, product_version)
  VALUES
    (v_license.id, v_device.id,
     CASE WHEN v_result = 'valid' THEN 'valid'
          WHEN v_result = 'expired' THEN 'expired'
          WHEN v_result = 'revoked' THEN 'revoked'
          ELSE 'invalid' END,
     false, p_ip, p_extension_version, v_product.current_version);

  -- remaining days
  IF v_license.expires_at IS NOT NULL THEN
    v_remaining := greatest(0, ceil(extract(epoch FROM (v_license.expires_at - now())) / 86400.0)::int);
  ELSE
    v_remaining := NULL;
  END IF;

  -- 11. Result payload.
  RETURN jsonb_build_object(
    'valid', v_result = 'valid',
    'status', v_license.status,
    'expires_at', v_license.expires_at,
    'device_limit', v_license.device_limit,
    'activations_count', v_license.activations_count,
    'update_required', v_update_req,
    'minimum_version', v_product.minimum_version,
    'remaining_days', v_remaining
  );
END;
$$;

-- -----------------------------------------------------------------------------
-- (f) rpc_activate_device(...) — idempotent device registration.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_activate_device(
  p_license_key text,
  p_fingerprint_hash text,
  p_device_info jsonb,
  p_nonce text,
  p_timestamp bigint,
  p_signature text,
  p_api_key_hash text,
  p_ip inet
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_license     public.licenses%ROWTYPE;
  v_device      public.devices%ROWTYPE;
  v_message     text;
  v_existing    boolean;
  v_active_cnt  int;
BEGIN
  -- Security checks ----------------------------------------------------------
  IF p_timestamp IS NULL OR abs(extract(epoch FROM now())::bigint - p_timestamp) > 300 THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'stale_timestamp');
  END IF;

  IF NOT public.rpc_consume_nonce(p_nonce) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'replay_detected');
  END IF;

  v_message := public._canonical_message(p_license_key, p_fingerprint_hash, NULL, p_nonce, p_timestamp);
  IF NOT public._verify_signature(v_message, p_signature) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'bad_signature');
  END IF;

  IF p_api_key_hash IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.api_keys
    WHERE key_hash = p_api_key_hash AND is_active = true
      AND (expires_at IS NULL OR expires_at > now())
  ) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'invalid_api_key');
  END IF;

  IF public.rpc_check_rate_limit(p_license_key, 'license_key', 'activate', 10, 60) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'rate_limited');
  END IF;

  -- Find + lock the license to serialize activation counting.
  SELECT * INTO v_license FROM public.licenses WHERE license_key = p_license_key FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'license_not_found');
  END IF;

  IF v_license.status NOT IN ('pending', 'trial', 'active') THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'license_not_activatable');
  END IF;

  -- Is this device already registered (idempotent re-activate)?
  SELECT * INTO v_device
    FROM public.devices
   WHERE license_id = v_license.id AND fingerprint_hash = p_fingerprint_hash;
  v_existing := FOUND;

  IF NOT v_existing THEN
    -- 2. Enforce device limit over currently-active devices.
    SELECT count(*) INTO v_active_cnt
      FROM public.devices
     WHERE license_id = v_license.id AND is_active = true;
    IF v_active_cnt >= v_license.device_limit THEN
      INSERT INTO public.activations (license_id, action, status, ip_address, request_nonce, error_code)
      VALUES (v_license.id, 'activate', 'blocked', p_ip, p_nonce, 'device_limit_reached');
      RETURN jsonb_build_object(
        'success', false,
        'error_code', 'device_limit_reached',
        'device_limit', v_license.device_limit,
        'activations_count', v_license.activations_count
      );
    END IF;
  END IF;

  -- 3. Upsert device (idempotent).
  INSERT INTO public.devices
    (license_id, user_id, fingerprint_hash, device_label, browser_info, os_info, timezone, is_active, last_seen_at)
  VALUES
    (v_license.id, v_license.user_id, p_fingerprint_hash,
     p_device_info ->> 'device_label',
     p_device_info -> 'browser_info',
     p_device_info -> 'os_info',
     p_device_info ->> 'timezone',
     true, now())
  ON CONFLICT (license_id, fingerprint_hash)
  DO UPDATE SET
     is_active = true,
     deactivated_at = NULL,
     deactivated_by = NULL,
     last_seen_at = now()
  RETURNING * INTO v_device;

  -- 4. Recompute activations_count from active devices (authoritative).
  SELECT count(*) INTO v_active_cnt
    FROM public.devices
   WHERE license_id = v_license.id AND is_active = true;

  UPDATE public.licenses
     SET activations_count = v_active_cnt,
         status = CASE WHEN status = 'pending' THEN 'active' ELSE status END
   WHERE id = v_license.id;

  -- 5. Audit the activation.
  INSERT INTO public.activations (license_id, device_id, action, status, ip_address, request_nonce)
  VALUES (v_license.id, v_device.id, 'activate', 'success', p_ip, p_nonce);

  -- 6. Result.
  RETURN jsonb_build_object(
    'success', true,
    'device_id', v_device.id,
    'activations_count', v_active_cnt,
    'device_limit', v_license.device_limit
  );
END;
$$;

-- -----------------------------------------------------------------------------
-- (g) rpc_deactivate_device(...)
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_deactivate_device(
  p_license_key text,
  p_fingerprint_hash text,
  p_nonce text,
  p_timestamp bigint,
  p_signature text,
  p_api_key_hash text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_license    public.licenses%ROWTYPE;
  v_device     public.devices%ROWTYPE;
  v_message    text;
  v_active_cnt int;
BEGIN
  IF p_timestamp IS NULL OR abs(extract(epoch FROM now())::bigint - p_timestamp) > 300 THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'stale_timestamp');
  END IF;

  IF NOT public.rpc_consume_nonce(p_nonce) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'replay_detected');
  END IF;

  v_message := public._canonical_message(p_license_key, p_fingerprint_hash, NULL, p_nonce, p_timestamp);
  IF NOT public._verify_signature(v_message, p_signature) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'bad_signature');
  END IF;

  IF p_api_key_hash IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.api_keys
    WHERE key_hash = p_api_key_hash AND is_active = true
      AND (expires_at IS NULL OR expires_at > now())
  ) THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'invalid_api_key');
  END IF;

  SELECT * INTO v_license FROM public.licenses WHERE license_key = p_license_key FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'license_not_found');
  END IF;

  SELECT * INTO v_device
    FROM public.devices
   WHERE license_id = v_license.id AND fingerprint_hash = p_fingerprint_hash AND is_active = true;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('success', false, 'error_code', 'device_not_active');
  END IF;

  UPDATE public.devices
     SET is_active = false, deactivated_at = now(), deactivated_by = 'user'
   WHERE id = v_device.id;

  SELECT count(*) INTO v_active_cnt
    FROM public.devices
   WHERE license_id = v_license.id AND is_active = true;

  UPDATE public.licenses SET activations_count = v_active_cnt WHERE id = v_license.id;

  INSERT INTO public.activations (license_id, device_id, action, status, request_nonce)
  VALUES (v_license.id, v_device.id, 'deactivate', 'success', p_nonce);

  RETURN jsonb_build_object(
    'success', true,
    'device_id', v_device.id,
    'activations_count', v_active_cnt,
    'device_limit', v_license.device_limit
  );
END;
$$;

-- -----------------------------------------------------------------------------
-- (h) rpc_create_license_after_payment(order_id, payment_id) — idempotent.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_create_license_after_payment(
  p_order_id uuid,
  p_payment_id text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_order      public.orders%ROWTYPE;
  v_plan       public.license_plans%ROWTYPE;
  v_product    public.products%ROWTYPE;
  v_license_id uuid;
  v_key        text;
  v_expires    timestamptz;
  v_trial_ends timestamptz;
  v_status     text;
  v_now        timestamptz := now();
BEGIN
  -- 1. Idempotency: a license already tied to this order?
  SELECT id INTO v_license_id
    FROM public.licenses
   WHERE metadata ->> 'order_id' = p_order_id::text
   LIMIT 1;
  IF v_license_id IS NOT NULL THEN
    RETURN v_license_id;
  END IF;

  -- 2. Resolve order → plan → product.
  SELECT * INTO v_order FROM public.orders WHERE id = p_order_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'order % not found', p_order_id;
  END IF;

  SELECT * INTO v_plan FROM public.license_plans WHERE id = v_order.plan_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'plan % not found for order %', v_order.plan_id, p_order_id;
  END IF;

  SELECT * INTO v_product FROM public.products WHERE id = v_order.product_id;

  -- 3. License key.
  v_key := public.rpc_generate_license_key();

  -- 4. Expiry from plan.duration_days (NULL => lifetime / no expiry).
  IF v_plan.plan_type = 'trial' THEN
    v_status := 'trial';
    v_trial_ends := v_now + make_interval(days => greatest(v_plan.trial_days, 1));
    v_expires := v_trial_ends;
  ELSE
    v_status := 'active';
    IF v_plan.duration_days IS NOT NULL THEN
      v_expires := v_now + make_interval(days => v_plan.duration_days);
    ELSE
      v_expires := NULL; -- lifetime
    END IF;
  END IF;

  -- 5. Insert license.
  INSERT INTO public.licenses
    (license_key, user_id, product_id, plan_id, status, device_limit,
     max_offline_hours, issued_at, expires_at, trial_ends_at, metadata)
  VALUES
    (v_key, v_order.user_id, v_order.product_id, v_order.plan_id, v_status,
     coalesce(v_plan.device_limit, 1), 72, v_now, v_expires, v_trial_ends,
     jsonb_build_object('order_id', p_order_id::text, 'payment_id', p_payment_id))
  RETURNING id INTO v_license_id;

  -- 6. Invoice (invoice_number auto-assigned by trigger).
  INSERT INTO public.invoices
    (invoice_number, order_id, user_id, line_items, subtotal, tax_amount, total, currency)
  VALUES
    ('PENDING', p_order_id, v_order.user_id,
     jsonb_build_array(jsonb_build_object(
       'description', coalesce(v_product.name, 'License') || ' — ' || v_plan.name,
       'quantity', 1,
       'unit_price', v_order.final_amount,
       'amount', v_order.final_amount
     )),
     v_order.original_amount, 0, v_order.final_amount, v_order.currency);

  RETURN v_license_id;
END;
$$;

-- -----------------------------------------------------------------------------
-- (i) rpc_renew_license(subscription_id) — extend on subscription.charged.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_renew_license(p_subscription_id text)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_sub     public.subscriptions%ROWTYPE;
  v_plan    public.license_plans%ROWTYPE;
  v_license public.licenses%ROWTYPE;
  v_base    timestamptz;
BEGIN
  SELECT * INTO v_sub FROM public.subscriptions
   WHERE razorpay_subscription_id = p_subscription_id;
  IF NOT FOUND OR v_sub.license_id IS NULL THEN
    RETURN false;
  END IF;

  SELECT * INTO v_license FROM public.licenses WHERE id = v_sub.license_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  SELECT * INTO v_plan FROM public.license_plans WHERE id = coalesce(v_sub.plan_id, v_license.plan_id);
  IF NOT FOUND OR v_plan.duration_days IS NULL THEN
    RETURN false;
  END IF;

  -- Extend from whichever is later: now or current expiry.
  v_base := greatest(coalesce(v_license.expires_at, now()), now());

  UPDATE public.licenses
     SET expires_at = v_base + make_interval(days => v_plan.duration_days),
         status = 'active'
   WHERE id = v_license.id;

  UPDATE public.subscriptions
     SET paid_count = paid_count + 1,
         remaining_count = CASE WHEN remaining_count IS NOT NULL
                                THEN greatest(remaining_count - 1, 0) END,
         status = 'active'
   WHERE id = v_sub.id;

  RETURN true;
END;
$$;

-- -----------------------------------------------------------------------------
-- (j) rpc_cleanup_expired_nonces() — housekeeping.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_cleanup_expired_nonces()
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_count int;
BEGIN
  WITH deleted AS (
    DELETE FROM public.nonces WHERE expires_at < now() RETURNING 1
  )
  SELECT count(*) INTO v_count FROM deleted;
  RETURN v_count;
END;
$$;

-- -----------------------------------------------------------------------------
-- (k) rpc_get_admin_stats() — dashboard aggregates.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.rpc_get_admin_stats()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_result jsonb;
BEGIN
  SELECT jsonb_build_object(
    'revenue_today', coalesce((
      SELECT sum(amount) FROM public.payments
      WHERE status = 'captured' AND captured_at >= date_trunc('day', now())), 0),
    'revenue_month', coalesce((
      SELECT sum(amount) FROM public.payments
      WHERE status = 'captured' AND captured_at >= date_trunc('month', now())), 0),
    'revenue_total', coalesce((
      SELECT sum(amount) FROM public.payments WHERE status = 'captured'), 0),
    'licenses_active', (SELECT count(*) FROM public.licenses WHERE status = 'active'),
    'licenses_trial', (SELECT count(*) FROM public.licenses WHERE status = 'trial'),
    'licenses_expired', (SELECT count(*) FROM public.licenses WHERE status = 'expired'),
    'customers_total', (SELECT count(*) FROM public.users WHERE deleted_at IS NULL),
    'customers_new_today', (
      SELECT count(*) FROM public.users
      WHERE deleted_at IS NULL AND created_at >= date_trunc('day', now())),
    'orders_today', (
      SELECT count(*) FROM public.orders WHERE created_at >= date_trunc('day', now())),
    'failed_payments_count', (
      SELECT count(*) FROM public.payments WHERE status = 'failed')
  ) INTO v_result;

  RETURN v_result;
END;
$$;
