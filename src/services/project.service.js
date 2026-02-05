import { Project } from "../models/project.models.js";
import { Task } from "../models/task.models.js";
import { Note } from "../models/note.models.js";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/api-error.js";
import { ErrorCodes } from "../utils/error-codes.js";
import { ProjectRolesEnum } from "../utils/constants.js";

export const createProject = async ({ name, description, ownerId }) => {
  if (!name) {
    throw new ApiError(400, "Project name is required", ErrorCodes.VALIDATION_ERROR);
  }

  const project = await Project.create({
    name,
    description,
    owner: ownerId,
    members: [{ user: ownerId, role: ProjectRolesEnum.MANAGER }],
  });

  return project;
};

export const getProjectsForUser = async (user) => {
  const matchStage =
    user.role === "admin"
      ? {}
      : {
          $or: [{ owner: user._id }, { "members.user": user._id }],
        };

  const projects = await Project.aggregate([
    { $match: matchStage },
    {
      $lookup: {
        from: "users",
        localField: "owner",
        foreignField: "_id",
        as: "owner",
      },
    },
    { $unwind: { path: "$owner", preserveNullAndEmptyArrays: true } },
    {
      $lookup: {
        from: "tasks",
        localField: "_id",
        foreignField: "project",
        as: "tasks",
      },
    },
    {
      $addFields: {
        taskCount: { $size: "$tasks" },
        memberCount: { $size: "$members" },
      },
    },
    {
      $project: {
        tasks: 0,
        "owner.password": 0,
        "owner.refreshToken": 0,
        "owner.emailVerificationToken": 0,
        "owner.emailVerificationExpiry": 0,
        "owner.forgotPasswordToken": 0,
        "owner.forgotPasswordExpiry": 0,
      },
    },
  ]);

  return projects;
};

export const getProjectDetails = async (projectId) => {
  const project = await Project.findById(projectId)
    .populate("owner", "username email fullName avatar")
    .populate("members.user", "username email fullName avatar");

  if (!project) {
    throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);
  }

  return project;
};

export const updateProject = async ({ projectId, name, description }) => {
  const project = await Project.findByIdAndUpdate(
    projectId,
    { name, description },
    { new: true, runValidators: true },
  );

  if (!project) throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);

  return project;
};

export const deleteProject = async (projectId) => {
  const project = await Project.findByIdAndDelete(projectId);
  if (!project) throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);

  await Promise.all([
    Task.deleteMany({ project: projectId }),
    Note.deleteMany({ project: projectId }),
  ]);

  return true;
};

export const addProjectMember = async ({ projectId, email, role }) => {
  const project = await Project.findById(projectId);
  if (!project) throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);

  const userToAdd = await User.findOne({ email: email.toLowerCase().trim() });
  if (!userToAdd) throw new ApiError(404, "User not found", ErrorCodes.USER_NOT_FOUND);

  const isAlreadyMember = project.members.some(
    (m) => m.user.toString() === userToAdd._id.toString(),
  );
  if (isAlreadyMember) throw new ApiError(400, "User is already a member", ErrorCodes.MEMBER_ALREADY_EXISTS);

  const resolvedRole = role || ProjectRolesEnum.MEMBER;
  if (![ProjectRolesEnum.MANAGER, ProjectRolesEnum.MEMBER].includes(resolvedRole)) {
    throw new ApiError(400, "Invalid role", ErrorCodes.INVALID_ROLE);
  }

  project.members.push({ user: userToAdd._id, role: resolvedRole });
  await project.save();

  return project;
};

export const updateProjectMemberRole = async ({ projectId, userId, role }) => {
  if (![ProjectRolesEnum.MANAGER, ProjectRolesEnum.MEMBER].includes(role)) {
    throw new ApiError(400, "Invalid role", ErrorCodes.INVALID_ROLE);
  }

  const project = await Project.findById(projectId);
  if (!project) throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);

  if (project.owner.toString() === userId) {
    throw new ApiError(400, "Cannot change role for project owner", ErrorCodes.INVALID_REQUEST);
  }

  const memberIndex = project.members.findIndex(
    (m) => m.user.toString() === userId,
  );
  if (memberIndex === -1) throw new ApiError(404, "Member not found in project", ErrorCodes.MEMBER_NOT_FOUND);

  project.members[memberIndex].role = role;
  await project.save();

  return project;
};

export const removeProjectMember = async ({ projectId, userId }) => {
  const project = await Project.findById(projectId);
  if (!project) throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);

  if (project.owner.toString() === userId) {
    throw new ApiError(400, "Cannot remove the project owner", ErrorCodes.INVALID_REQUEST);
  }

  project.members = project.members.filter((m) => m.user.toString() !== userId);
  await project.save();

  return project;
};

export const getProjectMembers = async (projectId) => {
  const project = await Project.findById(projectId)
    .populate("members.user", "username email fullName avatar")
    .populate("owner", "username email fullName avatar");

  if (!project) throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);

  const ownerId = project.owner?._id?.toString();
  const hasOwnerInMembers = project.members.some(
    (member) => member.user?._id?.toString() === ownerId,
  );

  if (!hasOwnerInMembers && project.owner) {
    return [
      { user: project.owner, role: ProjectRolesEnum.MANAGER },
      ...project.members,
    ];
  }

  return project.members;
};
