-- =============================================================================
-- 007_seed.sql
-- Baseline data: one demo product, three license plans, one feature flag.
-- Idempotent — safe to run on a fresh DB or via `supabase db reset`.
-- =============================================================================

DO $$
DECLARE
  v_product_id uuid;
BEGIN
  -- Demo product -------------------------------------------------------------
  SELECT id INTO v_product_id FROM public.products WHERE slug = 'bis-fire-assay-extension';

  IF v_product_id IS NULL THEN
    INSERT INTO public.products
      (name, slug, description, features, is_active, current_version, minimum_version,
       download_url, metadata)
    VALUES
      ('BIS Fire Assay Extension',
       'bis-fire-assay-extension',
       'Chrome extension that streamlines BIS fire assay reporting and compliance workflows for laboratories.',
       '["Automated assay data capture", "BIS-compliant report templates", "Offline-capable license", "Multi-device support"]'::jsonb,
       true,
       '1.0.0',
       '1.0.0',
       'https://chrome.google.com/webstore/detail/bis-fire-assay-extension',
       '{"category": "compliance", "vendor": "LicenseShield"}'::jsonb)
    RETURNING id INTO v_product_id;
  END IF;

  -- License plans ------------------------------------------------------------
  -- Trial: 7 days, free.
  IF NOT EXISTS (
    SELECT 1 FROM public.license_plans WHERE product_id = v_product_id AND plan_type = 'trial'
  ) THEN
    INSERT INTO public.license_plans
      (product_id, name, plan_type, price_inr, original_price_inr, device_limit,
       duration_days, trial_days, features, is_active, sort_order)
    VALUES
      (v_product_id, 'Trial', 'trial', 0, NULL, 1, 7, 7,
       '["Full features for 7 days", "1 device"]'::jsonb, true, 0);
  END IF;

  -- Monthly: ₹2999.
  IF NOT EXISTS (
    SELECT 1 FROM public.license_plans WHERE product_id = v_product_id AND plan_type = 'monthly'
  ) THEN
    INSERT INTO public.license_plans
      (product_id, name, plan_type, price_inr, original_price_inr, device_limit,
       duration_days, trial_days, features, is_active, sort_order)
    VALUES
      (v_product_id, 'Monthly', 'monthly', 2999.00, 3999.00, 2, 30, 0,
       '["All features", "2 devices", "Email support", "Monthly billing"]'::jsonb, true, 1);
  END IF;

  -- Yearly: ₹24999.
  IF NOT EXISTS (
    SELECT 1 FROM public.license_plans WHERE product_id = v_product_id AND plan_type = 'yearly'
  ) THEN
    INSERT INTO public.license_plans
      (product_id, name, plan_type, price_inr, original_price_inr, device_limit,
       duration_days, trial_days, features, is_active, sort_order)
    VALUES
      (v_product_id, 'Yearly', 'yearly', 24999.00, 35988.00, 3, 365, 0,
       '["All features", "3 devices", "Priority support", "Save 30% vs monthly"]'::jsonb, true, 2);
  END IF;
END;
$$;

-- Feature flag: maintenance_mode = false -------------------------------------
INSERT INTO public.feature_flags (key, value, description, enabled, rollout_percentage)
VALUES (
  'maintenance_mode',
  'false'::jsonb,
  'When enabled, the platform shows a maintenance page and pauses license verification.',
  false,
  0
)
ON CONFLICT (key) DO NOTHING;
