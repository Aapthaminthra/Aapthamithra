import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { prisma } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import { createOtp, deliverOtp, hashOtp, otpHashMatches } from "../services/otp.js";

const router = Router();
const loginSchema = z.object({ loginId: z.string().trim().min(3).max(200), password: z.string().min(10).max(200) });

router.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid login details" });
  const { loginId, password } = parsed.data;
  const user = await prisma.user.findFirst({ where: { OR: [{ publicId: loginId }, { email: loginId.toLowerCase() }] } });
  if (!user?.passwordHash || user.status !== "ACTIVE" || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: "Invalid credentials or inactive account" });
  }
  // Customer accounts require a second factor. Admin/employee MFA should also be enforced before production.
  if (user.role === "CUSTOMER") {
    const recent = await prisma.otpChallenge.findFirst({
      where: { userId: user.id, purpose: "CUSTOMER_LOGIN", consumedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: "desc" }
    });
    if (!recent) return res.status(409).json({ error: "Password accepted. Request a mobile OTP to finish sign-in.", otpRequired: true });
    return res.status(409).json({ error: "Complete the OTP step to finish sign-in.", otpRequired: true });
  }
  return issueSession(res, user);
});

router.post("/otp/request", async (req, res) => {
  const parsed = z.object({ loginId: z.string().trim().min(3).max(200), password: z.string().min(10).max(200) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter your customer ID" });
  const user = await prisma.user.findFirst({
    where: { publicId: parsed.data.loginId, role: "CUSTOMER", status: "ACTIVE" }
  });
  // Generic response helps reduce account enumeration.
  if (user) {
    const otp = createOtp();
    await prisma.otpChallenge.create({
      data: { userId: user.id, mobileE164: user.mobileE164, purpose: "CUSTOMER_LOGIN", codeHash: otp.codeHash, expiresAt: otp.expiresAt }
    });
    try { await deliverOtp(user.mobileE164, otp.code); }
    catch (err) { console.error("OTP delivery unavailable:", err.message); return res.status(503).json({ error: "OTP delivery is not configured. Contact the administrator." }); }
  }
  res.json({ message: "If the active customer ID exists, an OTP has been requested." });
});

router.post("/otp/verify", async (req, res) => {
  const parsed = z.object({ loginId: z.string().trim().min(3).max(200), code: z.string().regex(/^\d{6}$/) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid OTP request" });
  const user = await prisma.user.findFirst({ where: { publicId: parsed.data.loginId, role: "CUSTOMER", status: "ACTIVE" } });
  if (!user) return res.status(401).json({ error: "Invalid or expired OTP" });
  const challenge = await prisma.otpChallenge.findFirst({
    where: { userId: user.id, purpose: "CUSTOMER_LOGIN", consumedAt: null, expiresAt: { gt: new Date() }, attempts: { lt: Number(process.env.OTP_MAX_ATTEMPTS || 5) } },
    orderBy: { createdAt: "desc" }
  });
  if (!challenge || !otpHashMatches(challenge.codeHash, hashOtp(parsed.data.code))) {
    if (challenge) await prisma.otpChallenge.update({ where: { id: challenge.id }, data: { attempts: { increment: 1 } } });
    return res.status(401).json({ error: "Invalid or expired OTP" });
  }
  await prisma.otpChallenge.update({ where: { id: challenge.id }, data: { consumedAt: new Date() } });
  return issueSession(res, user);
});

function issueSession(res, user) {
  const token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET, {
    algorithm: "HS256", expiresIn: "8h", issuer: "aaptha-mithra"
  });
  res.cookie(process.env.COOKIE_NAME || "am_session", token, {
    httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000, path: "/"
  });
  return res.json({ user: { publicId: user.publicId, fullName: user.fullName, role: user.role, mustChangePassword: user.mustChangePassword } });
}
router.post("/logout", (_req, res) => {
  res.clearCookie(process.env.COOKIE_NAME || "am_session", { httpOnly: true, sameSite: "strict", path: "/" });
  res.status(204).end();
});
router.get("/me", requireAuth, (req, res) => res.json({
  user: { publicId: req.user.publicId, fullName: req.user.fullName, role: req.user.role, verificationStatus: req.user.verificationStatus, mustChangePassword: req.user.mustChangePassword }
}));
export default router;
