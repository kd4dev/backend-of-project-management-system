import { Task } from "../models/task.models.js";
import { Project } from "../models/project.models.js";
import { ApiError } from "../utils/api-error.js";
import { ErrorCodes } from "../utils/error-codes.js";
import { AvailableTaskStatus } from "../utils/constants.js";

const allowedTaskUpdates = [
  "title",
  "description",
  "status",
  "priority",
  "dueDate",
  "assignee",
  "attachments",
];

const allowedPriorities = ["low", "medium", "high"];

const isValidStatusTransition = (currentStatus, nextStatus) => {
  if (currentStatus === nextStatus) return true;
  const transitions = {
    todo: ["in_progress", "done"],
    in_progress: ["todo", "done"],
    done: ["todo", "in_progress"],
  };
  return transitions[currentStatus]?.includes(nextStatus);
};

const ensureAssigneeIsMember = async ({ projectId, assigneeId }) => {
  if (!assigneeId) return;
  const project = await Project.findById(projectId);
  if (!project) {
    throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);
  }

  const isOwner = project.owner.toString() === assigneeId.toString();
  const isMember = project.members.some(
    (m) => m.user.toString() === assigneeId.toString(),
  );

  if (!isOwner && !isMember) {
    throw new ApiError(
      400,
      "Assignee must be a project member",
      ErrorCodes.INVALID_REQUEST,
    );
  }
};

export const getProjectTasks = async (projectId) => {
  const tasks = await Task.find({ project: projectId })
    .populate("assignee", "username fullName avatar")
    .populate("subtasks.assignedTo", "username fullName avatar");

  return tasks;
};

export const createTask = async ({ projectId, payload }) => {
  const { title, description, status, priority, assignee, dueDate } = payload;

  if (!title) {
    throw new ApiError(400, "Task title is required", ErrorCodes.VALIDATION_ERROR);
  }

  const projectExists = await Project.exists({ _id: projectId });
  if (!projectExists) {
    throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);
  }

  if (status && !AvailableTaskStatus.includes(status)) {
    throw new ApiError(400, "Invalid task status", ErrorCodes.VALIDATION_ERROR);
  }

  if (priority && !allowedPriorities.includes(priority)) {
    throw new ApiError(400, "Invalid task priority", ErrorCodes.VALIDATION_ERROR);
  }

  if (dueDate && Number.isNaN(Date.parse(dueDate))) {
    throw new ApiError(400, "Invalid due date", ErrorCodes.VALIDATION_ERROR);
  }

  await ensureAssigneeIsMember({ projectId, assigneeId: assignee });

  const task = await Task.create({
    title,
    description,
    status,
    priority,
    assignee,
    dueDate,
    project: projectId,
  });

  return task;
};

export const getTaskDetails = async ({ projectId, taskId }) => {
  const task = await Task.findOne({ _id: taskId, project: projectId })
    .populate("assignee", "username fullName avatar")
    .populate("project")
    .populate("subtasks.assignedTo", "username fullName avatar");

  if (!task) throw new ApiError(404, "Task not found", ErrorCodes.TASK_NOT_FOUND);

  return task;
};

export const updateTask = async ({ projectId, taskId, updates }) => {
  const task = await Task.findOne({ _id: taskId, project: projectId });
  if (!task) throw new ApiError(404, "Task not found", ErrorCodes.TASK_NOT_FOUND);

  const sanitizedUpdates = Object.fromEntries(
    Object.entries(updates).filter(([key]) => allowedTaskUpdates.includes(key)),
  );

  if (sanitizedUpdates.status && !AvailableTaskStatus.includes(sanitizedUpdates.status)) {
    throw new ApiError(400, "Invalid task status", ErrorCodes.VALIDATION_ERROR);
  }

  if (sanitizedUpdates.priority && !allowedPriorities.includes(sanitizedUpdates.priority)) {
    throw new ApiError(400, "Invalid task priority", ErrorCodes.VALIDATION_ERROR);
  }

  if (sanitizedUpdates.dueDate && Number.isNaN(Date.parse(sanitizedUpdates.dueDate))) {
    throw new ApiError(400, "Invalid due date", ErrorCodes.VALIDATION_ERROR);
  }

  if (
    sanitizedUpdates.status &&
    !isValidStatusTransition(task.status, sanitizedUpdates.status)
  ) {
    throw new ApiError(
      400,
      "Invalid status transition",
      ErrorCodes.INVALID_STATUS_TRANSITION,
    );
  }

  if (sanitizedUpdates.assignee) {
    await ensureAssigneeIsMember({
      projectId,
      assigneeId: sanitizedUpdates.assignee,
    });
  }

  Object.assign(task, sanitizedUpdates);
  await task.save();

  return task;
};

export const deleteTask = async ({ projectId, taskId }) => {
  const task = await Task.findOneAndDelete({ _id: taskId, project: projectId });
  if (!task) throw new ApiError(404, "Task not found", ErrorCodes.TASK_NOT_FOUND);

  return true;
};

export const createSubtask = async ({ projectId, taskId, payload }) => {
  const { title, assignedTo } = payload;

  const task = await Task.findOne({ _id: taskId, project: projectId });
  if (!task) throw new ApiError(404, "Task not found", ErrorCodes.TASK_NOT_FOUND);

  if (!title) {
    throw new ApiError(400, "Subtask title is required", ErrorCodes.VALIDATION_ERROR);
  }

  if (assignedTo) {
    await ensureAssigneeIsMember({ projectId, assigneeId: assignedTo });
  }

  task.subtasks.push({ title, assignedTo, isCompleted: false });
  await task.save();

  return task;
};

export const updateSubtask = async ({
  projectId,
  taskId,
  subTaskId,
  payload,
  actorRole,
}) => {
  const { isCompleted, title, assignedTo } = payload;

  const task = await Task.findOne({ _id: taskId, project: projectId });
  if (!task) throw new ApiError(404, "Task not found", ErrorCodes.TASK_NOT_FOUND);

  const subtask = task.subtasks.id(subTaskId);
  if (!subtask) throw new ApiError(404, "Subtask not found", ErrorCodes.TASK_NOT_FOUND);

  const canManageSubtask = actorRole === "admin" || actorRole === "manager";

  if (isCompleted !== undefined) subtask.isCompleted = isCompleted;

  if (title) {
    if (!canManageSubtask) {
      throw new ApiError(403, "You do not have permission to edit subtask details", ErrorCodes.FORBIDDEN);
    }
    subtask.title = title;
  }

  if (assignedTo) {
    if (!canManageSubtask) {
      throw new ApiError(403, "You do not have permission to assign subtasks", ErrorCodes.FORBIDDEN);
    }
    await ensureAssigneeIsMember({ projectId, assigneeId: assignedTo });
    subtask.assignedTo = assignedTo;
  }

  await task.save();
  return task;
};

export const deleteSubtask = async ({ projectId, taskId, subTaskId }) => {
  const task = await Task.findOne({ _id: taskId, project: projectId });
  if (!task) throw new ApiError(404, "Task not found", ErrorCodes.TASK_NOT_FOUND);

  task.subtasks.pull(subTaskId);
  await task.save();

  return task;
};
