-- =============================================================================
-- 003_indexes.sql
-- Performance indexes for hot query paths.
-- =============================================================================

-- licenses --------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_licenses_license_key ON public.licenses (license_key);
CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON public.licenses (user_id);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON public.licenses (status);
-- Partial index: only active licenses need expiry sweeps.
CREATE INDEX IF NOT EXISTS idx_licenses_expires_at_active
  ON public.licenses (expires_at)
  WHERE status = 'active';

-- devices ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint_hash ON public.devices (fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_devices_license_id ON public.devices (license_id);

-- orders ----------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_orders_user_id ON public.orders (user_id);
CREATE INDEX IF NOT EXISTS idx_orders_razorpay_order_id ON public.orders (razorpay_order_id);

-- payments --------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_payments_razorpay_payment_id ON public.payments (razorpay_payment_id);
CREATE INDEX IF NOT EXISTS idx_payments_idempotency_key ON public.payments (idempotency_key);

-- nonces ----------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_nonces_nonce ON public.nonces (nonce);
CREATE INDEX IF NOT EXISTS idx_nonces_expires_at ON public.nonces (expires_at);

-- rate_limits -----------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup
  ON public.rate_limits (identifier, endpoint, window_start);

-- audit_logs ------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON public.audit_logs (resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON public.audit_logs (actor_id);

-- support_tickets -------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_support_tickets_user_id ON public.support_tickets (user_id);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status ON public.support_tickets (status);
