import { User } from "../models/user.models.js";
import { Project } from "../models/project.models.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import { ErrorCodes } from "../utils/error-codes.js";
import { getProjectRole } from "../utils/permissions.js";
import jwt from "jsonwebtoken";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) throw new ApiError(401, "Unauthorised request", ErrorCodes.UNAUTHORIZED);

  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry",
    );
    if (!user) throw new ApiError(401, "Invalid access token", ErrorCodes.UNAUTHORIZED);
    req.user = user;
    next();
  } 
  catch (error) {
    throw new ApiError(401, "Invalid access token", ErrorCodes.UNAUTHORIZED);
  }
});

export const requireGlobalRole = (allowRoles) =>
  asyncHandler(async (req, res, next) => {
    if (!req.user?.role) {
      throw new ApiError(403, "Access denied. No role assigned.", ErrorCodes.FORBIDDEN);
    }
    if (!allowRoles.includes(req.user.role)) {
      throw new ApiError(403, "Access denied. You do not have permission.", ErrorCodes.FORBIDDEN);
    }
    next();
  });

export const attachProject = asyncHandler(async (req, res, next) => {
  const { projectId } = req.params;
  if (!projectId) {
    throw new ApiError(400, "Project ID is required", ErrorCodes.INVALID_REQUEST);
  }

  const project = await Project.findById(projectId);
  if (!project) {
    throw new ApiError(404, "Project not found", ErrorCodes.PROJECT_NOT_FOUND);
  }

  const projectRole = getProjectRole(project, req.user?._id);

  if (!projectRole && req.user?.role !== "admin") {
    throw new ApiError(403, "You do not have access to this project", ErrorCodes.FORBIDDEN);
  }

  req.project = project;
  req.projectRole = projectRole;
  next();
});

export const requireProjectRole = (allowRoles) =>
  asyncHandler(async (req, res, next) => {
    if (req.user?.role === "admin") return next();
    const projectRole = req.projectRole || getProjectRole(req.project, req.user?._id);
    if (!projectRole || !allowRoles.includes(projectRole)) {
      throw new ApiError(403, "Access denied. You do not have permission.", ErrorCodes.FORBIDDEN);
    }
    next();
  });
