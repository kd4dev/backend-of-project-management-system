import express from "express";
import { verifyJWT, requireGlobalRole, attachProject } from "../middlewares/auth.middleware.js";
import {
  createProject,
  getProjects,
  getProjectDetails,
  updateProject,
  deleteProject,
  addMember,
  updateMemberRole,
  removeMember,
  getProjectMembers
} from "../controllers/project.controllers.js";

const router = express.Router();

router.use(verifyJWT);

router.route("/")
    .get(getProjects)
    .post(requireGlobalRole(["admin"]), createProject);

router.use("/:projectId", attachProject);

router.route("/:projectId")
    .get(getProjectDetails)
    .put(requireGlobalRole(["admin"]), updateProject)
    .delete(requireGlobalRole(["admin"]), deleteProject);

router.route("/:projectId/members")
    .get(getProjectMembers)
    .post(requireGlobalRole(["admin"]), addMember);

router.route("/:projectId/members/:userId")
    .put(requireGlobalRole(["admin"]), updateMemberRole)
    .delete(requireGlobalRole(["admin"]), removeMember);

export default router;
