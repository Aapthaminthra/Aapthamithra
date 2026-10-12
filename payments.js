import { Router } from "express";
import crypto from "node:crypto";
import { z } from "zod";
import { requireAuth, allowRoles } from "../middleware/auth.js";
import { prisma } from "../db.js";
import { audit } from "../services/audit.js";
const router = Router();

router.post("/membership/offline", requireAuth, allowRoles("CUSTOMER"), async (req, res) => {
  const p = z.object({ method: z.enum(["BANK_TRANSFER", "UPI", "CASH_AT_OFFICE"]), reference: z.string().trim().min(3).max(120) }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "Select a payment method and enter the transaction/reference number" });
  const membership = await prisma.membership.findUnique({ where: { userId: req.user.id } });
  if (!membership) return res.status(404).json({ error: "Membership application not found" });
  const payment = await prisma.payment.create({ data: {
    userId: req.user.id, mode: "OFFLINE", provider: "offline", amountPaise: 99900, currency: "INR",
    status: "PENDING", receipt: `am_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`,
    offlineMethod: p.data.method, offlineReference: p.data.reference
  }, select: { id: true, status: true, amountPaise: true, createdAt: true } });
  await audit(req, "OFFLINE_PAYMENT_SUBMITTED", "Payment", payment.id);
  res.status(201).json({ payment, message: "Payment details submitted for admin verification. Membership is not active until confirmed." });
});

router.post("/membership/order", requireAuth, allowRoles("CUSTOMER"), async (req, res) => {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    return res.status(503).json({ error: "Online payment gateway is not configured yet." });
  }
  const membership = await prisma.membership.findUnique({ where: { userId: req.user.id } });
  if (!membership) return res.status(404).json({ error: "Membership application not found" });
  const receipt = `am_${crypto.randomUUID().replaceAll("-", "").slice(0, 24)}`;
  const payment = await prisma.payment.create({ data: { userId: req.user.id, mode: "ONLINE", amountPaise: 99900, currency: "INR", status: "CREATED", receipt } });
  // Razorpay order creation: server-side, fixed amount from trusted config, never from request body.
  const auth = Buffer.from(`${process.env.RAZORPAY_KEY_ID}:${process.env.RAZORPAY_KEY_SECRET}`).toString("base64");
  const response = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST", headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json" },
    body: JSON.stringify({ amount: 99900, currency: "INR", receipt, notes: { paymentReference: payment.id, customerPublicId: req.user.publicId || "" } })
  });
  const order = await response.json();
  if (!response.ok || !order.id) {
    await prisma.payment.update({ where: { id: payment.id }, data: { status: "FAILED" } });
    return res.status(502).json({ error: "Could not create payment order. Please retry later." });
  }
  await prisma.payment.update({ where: { id: payment.id }, data: { providerOrderId: order.id, status: "PENDING" } });
  res.json({ keyId: process.env.RAZORPAY_KEY_ID, orderId: order.id, amount: order.amount, currency: order.currency, paymentReference: payment.id });
});

// Webhook route receives raw body before JSON parser in server.js.
router.post("/razorpay/webhook", async (req, res) => {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  const signature = req.get("x-razorpay-signature");
  if (!secret || !signature || !Buffer.isBuffer(req.body)) return res.status(400).send("Webhook not configured");
  const expected = crypto.createHmac("sha256", secret).update(req.body).digest("hex");
  const a = Buffer.from(signature), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(400).send("Invalid signature");
  let event;
  try { event = JSON.parse(req.body.toString("utf8")); } catch { return res.status(400).send("Invalid payload"); }
  if (event.event === "payment.captured") {
    const p = event.payload?.payment?.entity;
    if (!p?.order_id || !p?.id || p.amount !== 99900 || p.currency !== "INR") return res.status(400).send("Payment does not match expected membership amount");
    const payment = await prisma.payment.findFirst({ where: { providerOrderId: p.order_id, mode: "ONLINE" } });
    if (!payment) return res.status(404).send("Order not found");
    if (payment.status !== "PAID") {
      await prisma.$transaction(async tx => {
        await tx.payment.update({ where: { id: payment.id }, data: { status: "PAID", providerPaymentId: p.id, providerSignatureOkay: true, paidAt: new Date() } });
        await tx.membership.update({ where: { userId: payment.userId }, data: { status: "ACTIVE", startsAt: new Date(), expiresAt: new Date(Date.now() + 365*24*60*60*1000) } });
      });
    }
  }
  res.status(200).json({ received: true });
});
export default router;
