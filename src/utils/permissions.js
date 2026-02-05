import { ProjectRolesEnum } from "./constants.js";

export const getProjectRole = (project, userId) => {
  if (!project || !userId) return null;
  const userIdString = userId.toString();

  if (project.owner?.toString?.() === userIdString) {
    return ProjectRolesEnum.MANAGER;
  }

  const member = project.members?.find((m) => {
    const memberId = m.user?._id ? m.user._id.toString() : m.user?.toString?.();
    return memberId === userIdString;
  });

  return member?.role || null;
};

export const isProjectMember = (project, userId) => {
  return !!getProjectRole(project, userId);
};
