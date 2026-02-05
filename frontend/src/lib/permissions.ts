// Permission utility for role-based access control
export type UserRole = "admin" | "manager" | "member";
export type ProjectRole = "manager" | "member";

export interface PermissionCheck {
  canCreateProject: boolean;
  canUpdateProject: boolean;
  canDeleteProject: boolean;
  canManageMembers: boolean;
  canCreateTask: boolean;
  canUpdateTask: boolean;
  canDeleteTask: boolean;
  canCreateNote: boolean;
  canUpdateNote: boolean;
  canDeleteNote: boolean;
  canUpdateSubtaskStatus: boolean;
  canCreateSubtask: boolean;
  canDeleteSubtask: boolean;
}

export function getPermissions(role?: string, projectRole?: string): PermissionCheck {
  const userRole = role as UserRole | undefined;
  const isAdmin = userRole === "admin";
  const effectiveProjectRole = (isAdmin ? "manager" : (projectRole || userRole)) as
    | ProjectRole
    | undefined;

  return {
    // Project permissions
    canCreateProject: isAdmin,
    canUpdateProject: isAdmin,
    canDeleteProject: isAdmin,
    canManageMembers: isAdmin,

    // Task permissions
    canCreateTask: isAdmin || effectiveProjectRole === "manager",
    canUpdateTask: isAdmin || effectiveProjectRole === "manager",
    canDeleteTask: isAdmin || effectiveProjectRole === "manager",

    // Note permissions
    canCreateNote: isAdmin,
    canUpdateNote: isAdmin,
    canDeleteNote: isAdmin,

    // Subtask permissions
    canUpdateSubtaskStatus: true, // All roles can update subtask status
    canCreateSubtask: isAdmin || effectiveProjectRole === "manager",
    canDeleteSubtask: isAdmin || effectiveProjectRole === "manager",
  };
}

export function hasPermission(role?: string, permission?: keyof PermissionCheck): boolean {
  if (!permission) return false;
  const permissions = getPermissions(role);
  return permissions[permission];
}

// Role display helpers
export function getRoleBadgeVariant(role?: string): "default" | "secondary" | "destructive" {
  switch (role) {
    case "admin":
      return "destructive";
    case "manager":
      return "default";
    default:
      return "secondary";
  }
}

export function getRoleDisplayName(role?: string): string {
  switch (role) {
    case "admin":
      return "Admin";
    case "manager":
      return "Manager";
    case "member":
      return "Member";
    default:
      return "Unknown";
  }
}
