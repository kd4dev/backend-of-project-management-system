export const UserRolesEnum = {
  ADMIN: "admin",
  PROJECT_ADMIN: "project_admin",
  MEMBER: "member",
};

export const TaskStatusenum = {
  DONE: "done",
  TODO: "tofo",
  IN_PROGRESS: "in_progress",
};

export const AvailableUserRole = Object.values(UserRolesEnum);
export const AvailableTaskStatus = Object.values(TaskStatusenum);
