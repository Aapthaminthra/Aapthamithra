import "dotenv/config";
import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
const categories = [
["Home & Maintenance","home-maintenance","Repairs, cleaning, installation and maintenance."],
["Business Support","business-support","Operational and business coordination services."],
["Transport & Delivery","transport-delivery","Transport, delivery and logistics assistance."],
["Digital & Technology","digital-technology","Web, software, device and digital support."],
["Events & Bookings","events-bookings","Event planning and booking coordination."],
["Professional Services","professional-services","Connections to qualified professionals."],
["Shopping Assistance","shopping-assistance","Sourcing and personalized shopping support."],
["Other Services","other-services","Additional services offered by Aaptha Mithra."]
];
for (const [name,slug,description] of categories) await prisma.serviceCategory.upsert({where:{slug},update:{name,description},create:{name,slug,description}});
if (process.env.BOOTSTRAP_ADMIN_EMAIL && process.env.BOOTSTRAP_ADMIN_PASSWORD) {
 const email=process.env.BOOTSTRAP_ADMIN_EMAIL.toLowerCase();
 await prisma.user.upsert({where:{email},update:{},create:{
  publicId:"AM-ADMIN-001",role:"ADMIN",status:"ACTIVE",fullName:"Aaptha Mithra Administrator",
  email,mobileE164:"+910000000000",passwordHash:await bcrypt.hash(process.env.BOOTSTRAP_ADMIN_PASSWORD,12),verificationStatus:"VERIFIED"
 }});
 console.log("Bootstrap admin ensured. Remove bootstrap secrets after initial setup.");
}
await prisma.$disconnect();
