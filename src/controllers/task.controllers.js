import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";
import {
  createSubtask as createSubtaskService,
  createTask as createTaskService,
  deleteSubtask as deleteSubtaskService,
  deleteTask as deleteTaskService,
  getProjectTasks as getProjectTasksService,
  getTaskDetails as getTaskDetailsService,
  updateSubtask as updateSubtaskService,
  updateTask as updateTaskService,
} from "../services/task.service.js";

const getProjectTasks = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const tasks = await getProjectTasksService(projectId);

  return res
    .status(200)
    .json(new ApiResponse(200, tasks, "Tasks fetched successfully"));
});

const createTask = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const task = await createTaskService({ projectId, payload: req.body });

  return res
    .status(201)
    .json(new ApiResponse(201, task, "Task created successfully"));
});

const getTaskDetails = asyncHandler(async (req, res) => {
  const { projectId, taskId } = req.params;
  const task = await getTaskDetailsService({ projectId, taskId });

  return res
    .status(200)
    .json(new ApiResponse(200, task, "Task details fetched"));
});

const updateTask = asyncHandler(async (req, res) => {
  const { projectId, taskId } = req.params;
  const task = await updateTaskService({ projectId, taskId, updates: req.body });

  return res
    .status(200)
    .json(new ApiResponse(200, task, "Task updated successfully"));
});

const deleteTask = asyncHandler(async (req, res) => {
  const { projectId, taskId } = req.params;
  await deleteTaskService({ projectId, taskId });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Task deleted successfully"));
});

const createSubtask = asyncHandler(async (req, res) => {
  const { projectId, taskId } = req.params;
  const task = await createSubtaskService({
    projectId,
    taskId,
    payload: req.body,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, task, "Subtask added"));
});

const updateSubtask = asyncHandler(async (req, res) => {
  const { projectId, taskId, subTaskId } = req.params;
  const actorRole = req.user?.role === "admin" ? "admin" : req.projectRole;

  const task = await updateSubtaskService({
    projectId,
    taskId,
    subTaskId,
    payload: req.body,
    actorRole,
  });

  return res
    .status(200)
    .json(new ApiResponse(200, task, "Subtask updated"));
});

const deleteSubtask = asyncHandler(async (req, res) => {
  const { projectId, taskId, subTaskId } = req.params;
  const task = await deleteSubtaskService({ projectId, taskId, subTaskId });

  return res
    .status(200)
    .json(new ApiResponse(200, task, "Subtask deleted"));
});

export {
  getProjectTasks,
  createTask,
  getTaskDetails,
  updateTask,
  deleteTask,
  createSubtask,
  updateSubtask,
  deleteSubtask,
};
