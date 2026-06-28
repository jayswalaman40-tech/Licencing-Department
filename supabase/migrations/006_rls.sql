-- =============================================================================
-- 006_rls.sql
-- Row Level Security. Enabled on every table. Customers can only see their own
-- rows; admins (members of public.admins) get full access via is_admin().
--
-- NOTE: the service_role key and SECURITY DEFINER RPCs bypass RLS, so the
-- extension verification/activation flow and server-side webhooks are unaffected
-- by these policies.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- is_admin(user_id) — SECURITY DEFINER so policies can check membership without
-- recursing into the admins table's own RLS.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.is_admin(p_user_id uuid)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
  SELECT EXISTS (SELECT 1 FROM public.admins WHERE user_id = p_user_id);
$$;

-- -----------------------------------------------------------------------------
-- Enable RLS on all tables.
-- -----------------------------------------------------------------------------
ALTER TABLE public.users             ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admins            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.products          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.license_plans     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.licenses          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devices           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activations       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.verification_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.coupons           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.orders            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payments          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscriptions     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_logs      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.nonces            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limits       ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feature_flags     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_tickets   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_logs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invoices          ENABLE ROW LEVEL SECURITY;

-- =============================================================================
-- Admin full-access policies (apply to every table).
-- =============================================================================
CREATE POLICY admin_all_users             ON public.users             FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_admins            ON public.admins            FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_products          ON public.products          FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_license_plans     ON public.license_plans     FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_licenses          ON public.licenses          FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_devices           ON public.devices           FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_activations       ON public.activations       FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_verification_logs ON public.verification_logs FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_coupons           ON public.coupons           FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_orders            ON public.orders            FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_payments          ON public.payments          FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_subscriptions     ON public.subscriptions     FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_payment_logs      ON public.payment_logs      FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_api_keys          ON public.api_keys          FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_nonces            ON public.nonces            FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_rate_limits       ON public.rate_limits       FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_feature_flags     ON public.feature_flags     FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_support_tickets   ON public.support_tickets   FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_email_logs        ON public.email_logs        FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_audit_logs        ON public.audit_logs        FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_notifications     ON public.notifications     FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));
CREATE POLICY admin_all_invoices          ON public.invoices          FOR ALL TO authenticated USING (public.is_admin(auth.uid())) WITH CHECK (public.is_admin(auth.uid()));

-- =============================================================================
-- Customer (self-service) policies.
-- =============================================================================

-- users: read/update own profile.
CREATE POLICY users_select_own ON public.users
  FOR SELECT TO authenticated USING (auth.uid() = id);
CREATE POLICY users_update_own ON public.users
  FOR UPDATE TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- products / license_plans: public catalog (active rows readable by anyone).
CREATE POLICY products_select_active ON public.products
  FOR SELECT TO anon, authenticated USING (is_active = true AND deleted_at IS NULL);
CREATE POLICY license_plans_select_active ON public.license_plans
  FOR SELECT TO anon, authenticated USING (is_active = true);

-- licenses: read own.
CREATE POLICY licenses_select_own ON public.licenses
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- devices: read own.
CREATE POLICY devices_select_own ON public.devices
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- orders: read own.
CREATE POLICY orders_select_own ON public.orders
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- payments: read own.
CREATE POLICY payments_select_own ON public.payments
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- subscriptions: read own.
CREATE POLICY subscriptions_select_own ON public.subscriptions
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- invoices: read own.
CREATE POLICY invoices_select_own ON public.invoices
  FOR SELECT TO authenticated USING (auth.uid() = user_id);

-- support_tickets: read/create own; update own unless closed.
CREATE POLICY support_tickets_select_own ON public.support_tickets
  FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY support_tickets_insert_own ON public.support_tickets
  FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY support_tickets_update_own ON public.support_tickets
  FOR UPDATE TO authenticated
  USING (auth.uid() = user_id AND status <> 'closed')
  WITH CHECK (auth.uid() = user_id AND status <> 'closed');

-- notifications: read/update own (e.g. mark as read).
CREATE POLICY notifications_select_own ON public.notifications
  FOR SELECT TO authenticated USING (auth.uid() = user_id);
CREATE POLICY notifications_update_own ON public.notifications
  FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
