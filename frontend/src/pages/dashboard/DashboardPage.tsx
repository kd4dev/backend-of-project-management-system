import { useEffect, useState } from "react";
import apiClient from "@/api/client";
import { Link } from "react-router-dom";
import { CreateProjectDialog } from "@/components/CreateProjectDialog";
import { Folder, Plus, Users, CheckSquare } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { getPermissions } from "@/lib/permissions";
import { toast } from "sonner";

interface Project {
  _id: string;
  name: string;
  description?: string;
  owner?: { username: string };
  taskCount?: number;
  memberCount?: number;
}


export function DashboardPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const { user } = useAuth();
  const permissions = getPermissions(user?.role);

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      const response = await apiClient.get("/projects");
      setProjects(response.data.data);
    } catch (error) {
      console.error(error);
      toast.error("Failed to load projects");
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-10 w-48 bg-gray-200 dark:bg-gray-700 rounded-lg animate-pulse" />
        <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-44 bg-gray-200 dark:bg-gray-700 rounded-xl animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Projects</h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Manage and organize your team's work
          </p>
        </div>
        {permissions.canCreateProject && (
          <CreateProjectDialog onProjectCreated={fetchProjects} />
        )}
      </div>

      {/* Projects Grid */}
      {projects.length > 0 ? (
        <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {projects.map((project) => (
            <Link
              key={project._id}
              to={`/projects/${project._id}`}
              className="group relative bg-white/90 dark:bg-slate-950/60 rounded-2xl border border-slate-200/70 dark:border-slate-800/70 p-6 hover:shadow-lg hover:border-sky-300 dark:hover:border-sky-700 transition-all duration-200"
            >
              {/* Project Icon */}
              <div className="flex items-start justify-between mb-4">
                <div className="p-2.5 bg-sky-50 dark:bg-sky-900/20 rounded-lg group-hover:bg-sky-100 dark:group-hover:bg-sky-900/30 transition-colors">
                  <Folder className="w-5 h-5 text-sky-600 dark:text-sky-400" />
                </div>
              </div>

              {/* Project Name */}
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2 line-clamp-1">
                {project.name}
              </h3>

              {/* Project Description */}
              <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2 mb-4 min-h-[40px]">
                {project.description || "No description"}
              </p>

              {/* Project Stats */}
              <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
                <div className="flex items-center gap-1.5">
                  <CheckSquare className="w-4 h-4" />
                  <span>{project.taskCount || 0} tasks</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Users className="w-4 h-4" />
                  <span>{project.memberCount || 0} members</span>
                </div>
              </div>

              {/* Owner */}
              <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800/60">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-full bg-gradient-to-br from-sky-500 to-emerald-500 flex items-center justify-center text-white text-xs font-medium">
                    {project.owner?.username?.[0]?.toUpperCase() || "?"}
                  </div>
                  <span className="text-xs text-gray-600 dark:text-gray-400">
                    {project.owner?.username || "Unknown"}
                  </span>
                </div>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        /* Empty State */
        <div className="flex flex-col items-center justify-center py-16 px-4 bg-white/90 dark:bg-slate-950/60 rounded-2xl border border-slate-200/70 dark:border-slate-800/70">
          <div className="w-16 h-16 bg-slate-100 dark:bg-slate-800 rounded-full flex items-center justify-center mb-4">
            <Folder className="w-8 h-8 text-slate-400 dark:text-slate-500" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
            No projects yet
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center max-w-sm mb-6">
            {permissions.canCreateProject
              ? "Get started by creating your first project to organize your team's work."
              : "You don't have access to any projects yet. Contact an admin to get added."}
          </p>
          {permissions.canCreateProject && (
            <CreateProjectDialog onProjectCreated={fetchProjects}>
              <button className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors">
                <Plus className="w-4 h-4" />
                Create Project
              </button>
            </CreateProjectDialog>
          )}
        </div>
      )}
    </div>
  );
}
