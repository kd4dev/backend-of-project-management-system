// Fix admin user role in database
import "dotenv/config";
import mongoose from "mongoose";
import { User } from "./src/models/user.models.js";

async function fixAdminRole() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");

    // Find and update admin user
    const admin = await User.findOneAndUpdate(
      { email: "admin@example.com" },
      { role: "admin", isEmailVerified: true },
      { new: true }
    );

    if (admin) {
      console.log("✅ Admin role updated successfully!");
      console.log(`Email: ${admin.email}`);
      console.log(`Role: ${admin.role}`);
      console.log(`Verified: ${admin.isEmailVerified}`);
    } else {
      console.log("❌ Admin user not found");
    }
    
    process.exit(0);
  } catch (error) {
    console.error("❌ Error fixing admin role:", error);
    process.exit(1);
  }
}

fixAdminRole();
