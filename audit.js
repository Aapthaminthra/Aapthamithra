import { prisma } from "../db.js";
export async function audit(req, action, entityType, entityId = null, metadata = undefined) {
  await prisma.auditEvent.create({
    data: { actorId: req.user?.id ?? null, action, entityType, entityId, metadata, ipAddress: req.ip }
  });
}
