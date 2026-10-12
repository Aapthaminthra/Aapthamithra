import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.js";
import { requireAuth, allowRoles } from "../middleware/auth.js";
import { audit } from "../services/audit.js";
const router = Router();
router.get("/categories", async (_req, res) => res.json({ categories: await prisma.serviceCategory.findMany({ where: { isActive: true }, orderBy: { name: "asc" } }) }));
router.post("/requests", requireAuth, allowRoles("CUSTOMER"), async (req, res) => {
  const p = z.object({ categoryId: z.string().min(1), title: z.string().trim().min(3).max(120), description: z.string().trim().min(10).max(3000), locationText: z.string().trim().max(300).optional() }).safeParse(req.body);
  if (!p.success) return res.status(400).json({ error: "Invalid service request" });
  const membership = await prisma.membership.findUnique({ where: { userId: req.user.id } });
  if (!membership || membership.status !== "ACTIVE" || !membership.expiresAt || membership.expiresAt <= new Date()) return res.status(403).json({ error: "An active membership is required" });
  const publicId = `AM-S-${Date.now().toString().slice(-8)}${Math.floor(Math.random()*90+10)}`;
  const request = await prisma.serviceRequest.create({ data: { ...p.data, publicId, customerId: req.user.id }, select: { publicId: true, title: true, status: true, createdAt: true } });
  await audit(req, "SERVICE_REQUEST_CREATED", "ServiceRequest", request.publicId);
  res.status(201).json({ request });
});
router.get("/my-requests", requireAuth, allowRoles("CUSTOMER"), async (req, res) => res.json({ requests: await prisma.serviceRequest.findMany({ where: { customerId: req.user.id }, include: { category: { select: { name: true } }, employee: { select: { publicId: true, fullName: true } } }, orderBy: { createdAt: "desc" } }) }));
export default router;
