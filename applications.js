import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
const router = Router();
const schema = z.object({
  fullName: z.string().trim().min(2).max(120),
  mobileE164: z.string().trim().regex(/^\+[1-9]\d{7,14}$/),
  email: z.string().trim().email().max(200).optional().or(z.literal("")),
  verificationType: z.enum(["AADHAAR_MASKED", "PAN", "OTHER"]),
  verificationRef: z.string().trim().max(120).optional()
});
router.post("/", async (req, res) => {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Check the application fields and mobile number format" });
  const d = parsed.data;
  const existing = await prisma.user.findFirst({ where: { OR: [{ mobileE164: d.mobileE164 }, ...(d.email ? [{ email: d.email.toLowerCase() }] : [])] } });
  if (existing) return res.status(409).json({ error: "An application or account already exists for these details" });
  const application = await prisma.user.create({
    data: {
      role: "CUSTOMER", status: "PENDING", fullName: d.fullName, mobileE164: d.mobileE164,
      email: d.email ? d.email.toLowerCase() : null, verificationType: d.verificationType,
      verificationRef: d.verificationRef || null, verificationStatus: "PENDING",
      membership: { create: { status: "PENDING_PAYMENT", feePaise: 99900, currency: "INR" } }
    },
    select: { id: true, status: true, verificationStatus: true, createdAt: true }
  });
  res.status(201).json({ application, message: "Application submitted for administrator review." });
});
export default router;
