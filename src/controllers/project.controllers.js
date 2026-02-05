import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";
import {
  addProjectMember,
  createProject,
  deleteProject,
  getProjectDetails,
  getProjectMembers,
  getProjectsForUser,
  removeProjectMember,
  updateProject,
  updateProjectMemberRole,
} from "../services/project.service.js";

const createProjectController = asyncHandler(async (req, res) => {
  const { name, description } = req.body;
  const project = await createProject({
    name,
    description,
    ownerId: req.user._id,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, project, "Project created successfully"));
});

const getProjects = asyncHandler(async (req, res) => {
  const projects = await getProjectsForUser(req.user);
  return res
    .status(200)
    .json(new ApiResponse(200, projects, "Projects fetched successfully"));
});

const getProjectDetailsController = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const project = await getProjectDetails(projectId);

  return res
    .status(200)
    .json(new ApiResponse(200, project, "Project details fetched successfully"));
});

const updateProjectController = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { name, description } = req.body;

  const project = await updateProject({ projectId, name, description });

  return res
    .status(200)
    .json(new ApiResponse(200, project, "Project updated successfully"));
});

const deleteProjectController = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  await deleteProject(projectId);

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Project deleted successfully"));
});

const addMember = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { email, role } = req.body;

  const project = await addProjectMember({ projectId, email, role });

  return res
    .status(200)
    .json(new ApiResponse(200, project, "Member added successfully"));
});

const updateMemberRole = asyncHandler(async (req, res) => {
  const { projectId, userId } = req.params;
  const { role } = req.body;

  const project = await updateProjectMemberRole({ projectId, userId, role });

  return res
    .status(200)
    .json(new ApiResponse(200, project, "Member role updated"));
});

const removeMember = asyncHandler(async (req, res) => {
  const { projectId, userId } = req.params;

  const project = await removeProjectMember({ projectId, userId });

  return res
    .status(200)
    .json(new ApiResponse(200, project, "Member removed successfully"));
});

const getProjectMembersController = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const members = await getProjectMembers(projectId);

  return res
    .status(200)
    .json(new ApiResponse(200, members, "Members fetched successfully"));
});

export {
  createProjectController as createProject,
  getProjects,
  getProjectDetailsController as getProjectDetails,
  updateProjectController as updateProject,
  deleteProjectController as deleteProject,
  addMember,
  updateMemberRole,
  removeMember,
  getProjectMembersController as getProjectMembers,
};
