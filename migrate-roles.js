// Migration script to rename legacy role values
import "dotenv/config";
import mongoose from "mongoose";
import { User } from "./src/models/user.models.js";
import { Project } from "./src/models/project.models.js";

async function migrateRoles() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");

    const userResult = await User.updateMany(
      { role: "project_admin" },
      { $set: { role: "manager" } },
    );

    const projectResult = await Project.updateMany(
      { "members.role": "project_admin" },
      { $set: { "members.$[member].role": "manager" } },
      { arrayFilters: [{ "member.role": "project_admin" }] },
    );

    console.log("✅ User roles updated:", userResult.modifiedCount);
    console.log("✅ Project member roles updated:", projectResult.modifiedCount);
    process.exit(0);
  } catch (error) {
    console.error("❌ Role migration failed:", error);
    process.exit(1);
  }
}

migrateRoles();
