-- =============================================================================
-- 005_triggers.sql
-- updated_at maintenance, audit logging, and human-friendly number generation.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- _random_code(len) — uppercase alphanumeric (no ambiguous chars).
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._random_code(p_len int)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SET search_path = public, extensions
AS $$
DECLARE
  v_charset constant text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  v_len     constant int := length('ABCDEFGHJKMNPQRSTUVWXYZ23456789');
  v_bytes   bytea := extensions.gen_random_bytes(p_len);
  v_out     text := '';
  i         int;
BEGIN
  FOR i IN 0..p_len - 1 LOOP
    v_out := v_out || substr(v_charset, (get_byte(v_bytes, i) % v_len) + 1, 1);
  END LOOP;
  RETURN v_out;
END;
$$;

-- -----------------------------------------------------------------------------
-- updated_at triggers (only on tables that carry the column).
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_products_updated_at
  BEFORE UPDATE ON public.products
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_license_plans_updated_at
  BEFORE UPDATE ON public.license_plans
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_licenses_updated_at
  BEFORE UPDATE ON public.licenses
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_orders_updated_at
  BEFORE UPDATE ON public.orders
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_subscriptions_updated_at
  BEFORE UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE TRIGGER trg_support_tickets_updated_at
  BEFORE UPDATE ON public.support_tickets
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- -----------------------------------------------------------------------------
-- Audit logging: licenses status changes.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.audit_license_status()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status THEN
    INSERT INTO public.audit_logs
      (actor_id, actor_type, action, resource_type, resource_id, old_value, new_value)
    VALUES
      (NEW.user_id, 'system', 'license.status_changed', 'license', NEW.id,
       jsonb_build_object('status', OLD.status),
       jsonb_build_object('status', NEW.status, 'revoke_reason', NEW.revoke_reason));
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_licenses_audit_status
  AFTER UPDATE ON public.licenses
  FOR EACH ROW EXECUTE FUNCTION public.audit_license_status();

-- -----------------------------------------------------------------------------
-- Audit logging: payments status changes.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.audit_payment_status()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status THEN
    INSERT INTO public.audit_logs
      (actor_id, actor_type, action, resource_type, resource_id, old_value, new_value)
    VALUES
      (NEW.user_id, 'webhook', 'payment.status_changed', 'payment', NEW.id,
       jsonb_build_object('status', OLD.status),
       jsonb_build_object('status', NEW.status, 'amount', NEW.amount));
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_payments_audit_status
  AFTER UPDATE ON public.payments
  FOR EACH ROW EXECUTE FUNCTION public.audit_payment_status();

-- -----------------------------------------------------------------------------
-- Auto order_number: ORD-YYYYMMDD-XXXXX
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.gen_order_number()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NEW.order_number IS NULL OR NEW.order_number = '' OR NEW.order_number = 'PENDING' THEN
    LOOP
      NEW.order_number := 'ORD-' || to_char(now(), 'YYYYMMDD') || '-' || public._random_code(5);
      EXIT WHEN NOT EXISTS (SELECT 1 FROM public.orders WHERE order_number = NEW.order_number);
    END LOOP;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_orders_number
  BEFORE INSERT ON public.orders
  FOR EACH ROW EXECUTE FUNCTION public.gen_order_number();

-- -----------------------------------------------------------------------------
-- Auto ticket_number: TKT-XXXXX
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.gen_ticket_number()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NEW.ticket_number IS NULL OR NEW.ticket_number = '' OR NEW.ticket_number = 'PENDING' THEN
    LOOP
      NEW.ticket_number := 'TKT-' || public._random_code(5);
      EXIT WHEN NOT EXISTS (SELECT 1 FROM public.support_tickets WHERE ticket_number = NEW.ticket_number);
    END LOOP;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_support_tickets_number
  BEFORE INSERT ON public.support_tickets
  FOR EACH ROW EXECUTE FUNCTION public.gen_ticket_number();

-- -----------------------------------------------------------------------------
-- Auto invoice_number: INV-YYYY-MM-XXXXX
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.gen_invoice_number()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  IF NEW.invoice_number IS NULL OR NEW.invoice_number = '' OR NEW.invoice_number = 'PENDING' THEN
    LOOP
      NEW.invoice_number := 'INV-' || to_char(now(), 'YYYY-MM') || '-' || public._random_code(5);
      EXIT WHEN NOT EXISTS (SELECT 1 FROM public.invoices WHERE invoice_number = NEW.invoice_number);
    END LOOP;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_invoices_number
  BEFORE INSERT ON public.invoices
  FOR EACH ROW EXECUTE FUNCTION public.gen_invoice_number();
