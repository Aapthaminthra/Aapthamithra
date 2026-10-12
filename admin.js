import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "../db.js";
import { requireAuth, allowRoles } from "../middleware/auth.js";
import { audit } from "../services/audit.js";
const router = Router();
router.use(requireAuth, allowRoles("ADMIN"));

router.get("/summary", async (_req, res) => {
  const [pending, activeCustomers, activeEmployees, activeMemberships, openRequests, pendingPayments] = await Promise.all([
    prisma.user.count({ where: { role: "CUSTOMER", status: "PENDING" } }),
    prisma.user.count({ where: { role: "CUSTOMER", status: "ACTIVE" } }),
    prisma.user.count({ where: { role: "EMPLOYEE", status: "ACTIVE" } }),
    prisma.membership.count({ where: { status: "ACTIVE" } }),
    prisma.serviceRequest.count({ where: { status: { in: ["SUBMITTED", "REVIEWING", "ASSIGNED", "IN_PROGRESS"] } } }),
    prisma.payment.count({ where: { mode: "OFFLINE", status: "PENDING" } })
  ]);
  res.json({ pendingApplications: pending, activeCustomers, activeEmployees, activeMemberships, openServiceRequests: openRequests, offlinePaymentsToReview: pendingPayments });
});
router.get("/applications", async (_req, res) => {
  const applications = await prisma.user.findMany({
    where: { role: "CUSTOMER", status: "PENDING" },
    select: { id: true, fullName: true, mobileE164: true, email: true, verificationType: true, verificationStatus: true, createdAt: true, membership: { select: { status: true, feePaise: true } }, payments: { select: { id: true, mode: true, status: true, amountPaise: true, offlineMethod: true, offlineReference: true, createdAt: true }, orderBy: { createdAt: "desc" }, take: 3 } },
    orderBy: { createdAt: "asc" }
  });
  res.json({ applications });
});
router.post("/applications/:id/verification", async (req, res) => {
  const p = z.object({ status: z.enum(["VERIFIED", "REJECTED"]), note: z.string().max(500).optional() }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "Invalid verification update" });
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!user || user.role !== "CUSTOMER") return res.status(404).json({ error: "Application not found" });
  await prisma.user.update({ where: { id: user.id }, data: { verificationStatus: p.data.status } });
  await audit(req, "IDENTITY_REVIEWED", "User", user.id, { status: p.data.status, note: p.data.note });
  res.json({ ok: true });
});
router.post("/applications/:id/approve", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.id }, include: { membership: true, payments: { where: { status: "PAID" }, take: 1 } } });
  if (!user || user.role !== "CUSTOMER" || user.status !== "PENDING") return res.status(404).json({ error: "Pending application not found" });
  if (user.verificationStatus !== "VERIFIED") return res.status(409).json({ error: "Identity verification must be VERIFIED first" });
  if (user.membership?.status !== "ACTIVE" || user.payments.length === 0) return res.status(409).json({ error: "A paid membership must be confirmed first" });
  const publicId = `AM-C-${cryptoId()}`;
  await prisma.user.update({ where: { id: user.id }, data: { status: "ACTIVE", publicId, approvedAt: new Date(), approvedById: req.user.id } });
  await audit(req, "CUSTOMER_APPROVED", "User", user.id, { publicId });
  res.json({ ok: true, customerId: publicId });
});
function cryptoId(){ return `${Date.now().toString().slice(-8)}${Math.floor(Math.random()*90+10)}`; }
router.post("/applications/:id/reject", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!user || user.role !== "CUSTOMER" || user.status !== "PENDING") return res.status(404).json({ error: "Pending application not found" });
  await prisma.user.update({ where: { id: user.id }, data: { status: "REJECTED" } });
  await audit(req, "CUSTOMER_REJECTED", "User", user.id);
  res.json({ ok: true });
});
router.get("/payments/offline", async (_req, res) => {
  const payments = await prisma.payment.findMany({
    where: { mode: "OFFLINE", status: "PENDING" },
    include: { user: { select: { id: true, fullName: true, mobileE164: true, status: true, membership: true } } },
    orderBy: { createdAt: "asc" }
  });
  res.json({ payments });
});
router.post("/payments/offline/:id/confirm", async (req, res) => {
  const p = z.object({ note: z.string().trim().min(3).max(500) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "Provide an audit note explaining how payment was verified" });
  const payment = await prisma.payment.findUnique({ where: { id: req.params.id } });
  if (!payment || payment.mode !== "OFFLINE" || payment.status !== "PENDING") return res.status(404).json({ error: "Pending offline payment not found" });
  await prisma.$transaction(async tx => {
    await tx.payment.update({ where: { id: payment.id }, data: { status: "PAID", paidAt: new Date(), confirmedById: req.user.id, confirmedAt: new Date(), adminNote: p.data.note } });
    await tx.membership.update({ where: { userId: payment.userId }, data: { status: "ACTIVE", startsAt: new Date(), expiresAt: new Date(Date.now() + 365*24*60*60*1000) } });
  });
  await audit(req, "OFFLINE_PAYMENT_CONFIRMED", "Payment", payment.id, { note: p.data.note });
  res.json({ ok: true });
});
router.post("/payments/offline/:id/reject", async (req, res) => {
  const p = z.object({ note: z.string().trim().min(3).max(500) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "Provide a reason" });
  const payment = await prisma.payment.findUnique({ where: { id: req.params.id } });
  if (!payment || payment.mode !== "OFFLINE" || payment.status !== "PENDING") return res.status(404).json({ error: "Pending offline payment not found" });
  await prisma.payment.update({ where: { id: payment.id }, data: { status: "FAILED", confirmedById: req.user.id, confirmedAt: new Date(), adminNote: p.data.note } });
  await audit(req, "OFFLINE_PAYMENT_REJECTED", "Payment", payment.id, { note: p.data.note });
  res.json({ ok: true });
});
router.post("/employees", async (req, res) => {
  const p = z.object({ fullName: z.string().trim().min(2).max(120), mobileE164: z.string().regex(/^\+[1-9]\d{7,14}$/), email: z.string().email(), temporaryPassword: z.string().min(12).max(200) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "Invalid employee details" });
  const publicId = `AM-E-${cryptoId()}`;
  const employee = await prisma.user.create({ data: { publicId, role: "EMPLOYEE", status: "ACTIVE", fullName: p.data.fullName, mobileE164: p.data.mobileE164, email: p.data.email.toLowerCase(), passwordHash: await bcrypt.hash(p.data.temporaryPassword, 12), mustChangePassword: true }, select: { publicId: true, fullName: true, email: true } });
  await audit(req, "EMPLOYEE_CREATED", "User", publicId);
  res.status(201).json({ employee });
});
router.get("/service-requests", async (_req, res) => {
  const requests = await prisma.serviceRequest.findMany({ include: { category: { select: { name: true } }, customer: { select: { publicId: true, fullName: true, mobileE164: true } }, employee: { select: { publicId: true, fullName: true } } }, orderBy: { createdAt: "desc" }, take: 100 });
  res.json({ requests });
});
export default router;
