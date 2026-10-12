import crypto from "node:crypto";

const ttl = Number(process.env.OTP_TTL_SECONDS || 300);
const hmacSecret = process.env.OTP_HMAC_SECRET || "";
export function createOtp() {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  if (hmacSecret.length < 32) throw new Error("OTP_HMAC_SECRET must be at least 32 characters");
  const codeHash = crypto.createHmac("sha256", hmacSecret).update(code).digest("hex");
  return { code, codeHash, expiresAt: new Date(Date.now() + ttl * 1000) };
}
export function hashOtp(code) {
  return crypto.createHmac("sha256", hmacSecret).update(code).digest("hex");
}
export function otpHashMatches(a, b) {
  const aa = Buffer.from(a || "");
  const bb = Buffer.from(b || "");
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
export async function deliverOtp(mobileE164, code) {
  // Development only: do not use console delivery in production.
  // Replace with an SMS provider (for example, a verified transactional SMS service).
  if (process.env.NODE_ENV === "production" || process.env.OTP_PROVIDER !== "console") {
    throw new Error("SMS OTP provider adapter is not configured");
  }
  console.log(`[DEV ONLY] OTP for ${mobileE164}: ${code}`);
}
