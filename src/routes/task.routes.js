import express from "express";
import { verifyJWT, attachProject, requireProjectRole } from "../middlewares/auth.middleware.js";
import {
    getProjectTasks,
    createTask,
    getTaskDetails,
    updateTask,
    deleteTask,
    createSubtask,
    updateSubtask,
    deleteSubtask
} from "../controllers/task.controllers.js";

const router = express.Router();

router.use(verifyJWT);
router.use("/:projectId", attachProject);

// Project Tasks
router.route("/:projectId")
    .get(getProjectTasks)
    .post(requireProjectRole(["manager"]), createTask);

// Individual Task
router.route("/:projectId/t/:taskId")
    .get(getTaskDetails)
    .put(requireProjectRole(["manager"]), updateTask)
    .delete(requireProjectRole(["manager"]), deleteTask);

// Subtasks
router.route("/:projectId/t/:taskId/subtasks")
    .post(requireProjectRole(["manager"]), createSubtask);

router.route("/:projectId/t/:taskId/subtasks/:subTaskId")
    .put(updateSubtask) // Members can update subtask status
    .delete(requireProjectRole(["manager"]), deleteSubtask);

export default router;
