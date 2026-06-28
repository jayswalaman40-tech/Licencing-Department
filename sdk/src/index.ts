/**
 * LicenseShield SDK
 * -----------------
 * Lightweight client for Chrome Extensions to activate, verify, and
 * deactivate LicenseShield licenses. All requests are HMAC-signed with a
 * per-request nonce + timestamp to prevent replay attacks.
 *
 * Usage:
 *   const client = new LicenseShieldClient({
 *     baseUrl: "https://app.example.com",
 *     apiKey: "lsk_live_xxx",
 *     productId: "<uuid>",
 *     secret: "<shared-hmac-secret>",
 *   });
 *   await client.activate(licenseKey);
 *   const result = await client.verify(licenseKey);
 */

export interface LicenseShieldConfig {
  /** Base URL of the LicenseShield API (no trailing slash). */
  baseUrl: string;
  /** Public API key issued for this product. */
  apiKey: string;
  /** Product UUID this extension belongs to. */
  productId: string;
  /** Shared HMAC secret used to sign requests. */
  secret: string;
  /** Extension version string (e.g. from manifest.version). */
  extensionVersion?: string;
  /** Max hours a cached "valid" result is trusted while offline. */
  maxOfflineHours?: number;
}

export interface VerifyResult {
  valid: boolean;
  status: string;
  expires_at: string | null;
  device_limit: number;
  activations_count: number;
  update_required: boolean;
  minimum_version: string | null;
  remaining_days: number | null;
  offline?: boolean;
}

export interface ActivateResult {
  success: boolean;
  device_id: string | null;
  activations_count: number;
  device_limit: number;
  error_code?: string;
}

export interface DeactivateResult {
  success: boolean;
  error_code?: string;
}

const NONCE_BYTES = 16;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  return toHex(bytes);
}

async function hmacSha256(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return toHex(new Uint8Array(sig));
}

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(input));
  return toHex(new Uint8Array(digest));
}

/**
 * Build a stable device fingerprint from available browser signals.
 * In an extension's service worker the surface is limited, so callers may
 * pass their own seed (e.g. a persisted random id stored in chrome.storage).
 */
export async function computeFingerprint(seed?: string): Promise<string> {
  const parts = [
    seed ?? "",
    typeof navigator !== "undefined" ? navigator.userAgent : "",
    typeof navigator !== "undefined" ? navigator.language : "",
    typeof Intl !== "undefined"
      ? Intl.DateTimeFormat().resolvedOptions().timeZone
      : "",
  ];
  return sha256Hex(parts.join("|"));
}

export class LicenseShieldClient {
  private readonly config: Required<
    Pick<LicenseShieldConfig, "baseUrl" | "apiKey" | "productId" | "secret">
  > &
    LicenseShieldConfig;

  constructor(config: LicenseShieldConfig) {
    this.config = {
      extensionVersion: "0.0.0",
      maxOfflineHours: 72,
      ...config,
      baseUrl: config.baseUrl.replace(/\/+$/, ""),
    };
  }

  /**
   * Build the canonical message exactly as the server's
   * `public._canonical_message()` does:
   *   concat_ws('|', license_key, fingerprint_hash, product_id|'', nonce, ts)
   * then HMAC-SHA256 it with the shared secret (hex output).
   */
  private async sign(
    licenseKey: string,
    fingerprint: string,
    productId: string | null,
    nonce: string,
    timestamp: number,
  ): Promise<string> {
    const message = [
      licenseKey,
      fingerprint,
      productId ?? "",
      nonce,
      String(timestamp),
    ].join("|");
    return hmacSha256(this.config.secret, message);
  }

  private async post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    const res = await fetch(`${this.config.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": this.config.apiKey,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`LicenseShield request failed: ${res.status}`);
    }
    return (await res.json()) as T;
  }

  async activate(
    licenseKey: string,
    fingerprintSeed?: string,
  ): Promise<ActivateResult> {
    const fingerprint = await computeFingerprint(fingerprintSeed);
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    // Activate signs without product_id (server passes NULL).
    const signature = await this.sign(
      licenseKey,
      fingerprint,
      null,
      nonce,
      timestamp,
    );
    return this.post<ActivateResult>("/api/v1/activate", {
      license_key: licenseKey,
      fingerprint_hash: fingerprint,
      product_id: this.config.productId,
      timestamp,
      nonce,
      signature,
      device_info: {
        user_agent:
          typeof navigator !== "undefined" ? navigator.userAgent : null,
      },
    });
  }

  async verify(
    licenseKey: string,
    fingerprintSeed?: string,
  ): Promise<VerifyResult> {
    const fingerprint = await computeFingerprint(fingerprintSeed);
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    // Verify signs with product_id.
    const signature = await this.sign(
      licenseKey,
      fingerprint,
      this.config.productId,
      nonce,
      timestamp,
    );
    return this.post<VerifyResult>("/api/v1/verify", {
      license_key: licenseKey,
      fingerprint_hash: fingerprint,
      product_id: this.config.productId,
      timestamp,
      nonce,
      signature,
      extension_version: this.config.extensionVersion,
    });
  }

  async deactivate(
    licenseKey: string,
    fingerprintSeed?: string,
  ): Promise<DeactivateResult> {
    const fingerprint = await computeFingerprint(fingerprintSeed);
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    // Deactivate signs without product_id (server passes NULL).
    const signature = await this.sign(
      licenseKey,
      fingerprint,
      null,
      nonce,
      timestamp,
    );
    return this.post<DeactivateResult>("/api/v1/deactivate", {
      license_key: licenseKey,
      fingerprint_hash: fingerprint,
      timestamp,
      nonce,
      signature,
    });
  }
}

export default LicenseShieldClient;
