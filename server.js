import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { prisma } from "./db.js";
import authRoutes from "./routes/auth.js";
import applicationRoutes from "./routes/applications.js";
import adminRoutes from "./routes/admin.js";
import serviceRoutes from "./routes/services.js";
import paymentRoutes from "./routes/payments.js";

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters");
if (!process.env.OTP_HMAC_SECRET || process.env.OTP_HMAC_SECRET.length < 32) throw new Error("OTP_HMAC_SECRET must be at least 32 characters");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: process.env.APP_ORIGIN || "http://localhost:3000", credentials: true }));
app.use(cookieParser());
// Webhook needs raw body for signature verification; register before express.json().
app.use("/api/payments/razorpay/webhook", express.raw({ type: "application/json" }));
app.use(express.json({ limit: "100kb" }));
app.use(express.static("public"));
app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: 150, standardHeaders: "draft-7", legacyHeaders: false }));
app.use("/api/auth", authRoutes);
app.use("/api/applications", applicationRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/services", serviceRoutes);
app.use("/api/payments", paymentRoutes);
app.get("/api/health", (_req, res) => res.json({ ok: true, app: "Aaptha Mithra" }));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: "Unexpected server error" }); });
const server = app.listen(Number(process.env.PORT || 3000), () => console.log(`Aaptha Mithra listening on port ${process.env.PORT || 3000}`));
async function shutdown(){ server.close(async()=>{await prisma.$disconnect();process.exit(0);}); }
process.on("SIGINT",shutdown); process.on("SIGTERM",shutdown);
