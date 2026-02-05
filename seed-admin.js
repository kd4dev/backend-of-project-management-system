// Seed script to create an admin user for development
import "dotenv/config";
import mongoose from "mongoose";
import { User } from "./src/models/user.models.js";

const ADMIN_USER = {
  username: "admin",
  email: "admin@example.com",
  password: "Admin123!",
  fullName: "Admin User",
  role: "admin",
  isEmailVerified: true, // Skip verification for dev
};

async function seedAdmin() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");

    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: ADMIN_USER.email });
    if (existingAdmin) {
      console.log("✅ Admin user already exists");
      console.log(`Email: ${ADMIN_USER.email}`);
      console.log(`Password: ${ADMIN_USER.password}`);
      console.log(`Role: ${existingAdmin.role}`);
      process.exit(0);
    }

    // Create admin user
    const admin = await User.create(ADMIN_USER);
    console.log("✅ Admin user created successfully!");
    console.log(`Email: ${ADMIN_USER.email}`);
    console.log(`Password: ${ADMIN_USER.password}`);
    console.log(`Role: ${admin.role}`);
    
    process.exit(0);
  } catch (error) {
    console.error("❌ Error seeding admin:", error);
    process.exit(1);
  }
}

seedAdmin();
