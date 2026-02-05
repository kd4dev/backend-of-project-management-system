export const UserRolesEnum = {
  ADMIN: "admin",
  MANAGER: "manager",
  MEMBER: "member",
};

export const ProjectRolesEnum = {
  MANAGER: "manager",
  MEMBER: "member",
};

export const TaskStatusEnum = {
  DONE: "done",
  TODO: "todo",
  IN_PROGRESS: "in_progress",
};

export const AvailableUserRole = Object.values(UserRolesEnum);
export const AvailableProjectRole = Object.values(ProjectRolesEnum);
export const AvailableTaskStatus = Object.values(TaskStatusEnum);
