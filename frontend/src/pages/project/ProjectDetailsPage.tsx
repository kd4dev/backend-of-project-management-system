import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import apiClient from "@/api/client";
import { CreateTaskDialog } from "@/components/CreateTaskDialog";
import { EditTaskDialog } from "@/components/EditTaskDialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { format } from "date-fns";
import { MoreVertical, Circle, AlertCircle, CheckCircle2, Calendar, User, Clock, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ProjectMembers } from "@/components/ProjectMembers";
import { ProjectNotes } from "@/components/ProjectNotes";
import { getDueDateStatus } from "@/lib/dueDateUtils";
import { TaskFilters } from "@/components/TaskFilters";
import { useAuth } from "@/context/AuthContext";
import { getPermissions } from "@/lib/permissions";

interface Task {
  _id: string;
  title: string;
  description: string;
  status: "todo" | "in_progress" | "done";
  priority: "low" | "medium" | "high";
  dueDate?: string;
  assignee?: { _id: string; username: string; avatar?: { url: string } };
}

interface Project {
  _id: string;
  name: string;
  description?: string;
  owner: { _id: string; username: string };
  members: { role: string; user: { _id: string; username: string } }[];
}

export default function ProjectDetailsPage() {
  const { projectId } = useParams();
  const [project, setProject] = useState<Project | null>(null);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [taskToDelete, setTaskToDelete] = useState<Task | null>(null);
  const [isDeletingTask, setIsDeletingTask] = useState(false);
  const [errorState, setErrorState] = useState<null | "forbidden" | "not_found" | "error">(null);
  const { user } = useAuth();
  
  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [priorityFilter, setPriorityFilter] = useState("all");
  const [assigneeFilter, setAssigneeFilter] = useState("all");

  useEffect(() => {
    fetchData();
  }, [projectId]);

  const fetchData = async () => {
    if (!projectId) return;
    try {
      setIsLoading(true);
      setErrorState(null);
      const [projectRes, tasksRes] = await Promise.all([
        apiClient.get(`/projects/${projectId}`),
        apiClient.get(`/tasks/${projectId}`),
      ]);
      setProject(projectRes.data.data);
      setTasks(tasksRes.data.data);
    } catch (error) {
      console.error(error);
      const status = (error as any)?.response?.status;
      if (status === 403) setErrorState("forbidden");
      else if (status === 404) setErrorState("not_found");
      else setErrorState("error");
      toast.error("Failed to load project data");
    } finally {
      setIsLoading(false);
    }
  };

  const projectRole = useMemo(() => {
    if (!project || !user) return null;
    if (user.role === "admin") return "manager";
    if (project.owner?._id === user._id) return "manager";
    const membership = project.members?.find(
      (member) => member.user?._id === user._id,
    );
    return membership?.role || null;
  }, [project, user]);

  const permissions = useMemo(() => getPermissions(user?.role, projectRole || undefined), [user?.role, projectRole]);
  const showTaskMenu = permissions.canUpdateTask || permissions.canDeleteTask;

  const getTasksByStatus = (status: string) => {
    return tasks.filter((task) => {
      // Status filter
      if (task.status !== status) return false;
      
      // Search filter
      if (searchQuery && !task.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
          !task.description?.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false;
      }
      
      // Priority filter
      if (priorityFilter !== "all" && task.priority !== priorityFilter) {
        return false;
      }
      
      // Assignee filter
      if (assigneeFilter !== "all") {
        if (assigneeFilter === "unassigned" && task.assignee) return false;
        if (assigneeFilter !== "unassigned" && task.assignee?._id !== assigneeFilter) return false;
      }
      
      return true;
    });
  };

  const getUniqueAssignees = () => {
    const assignees = new Map<string, { _id: string; username: string }>();
    tasks.forEach((task) => {
      if (task.assignee) {
        assignees.set(task.assignee._id, {
          _id: task.assignee._id,
          username: task.assignee.username,
        });
      }
    });
    return Array.from(assignees.values());
  };

  const handleStatusChange = async (taskId: string, newStatus: "todo" | "in_progress" | "done") => {
    if (!permissions.canUpdateTask) {
      toast.error("You don't have permission to update this task.");
      return;
    }
    try {
      await apiClient.put(`/tasks/${projectId}/t/${taskId}`, { status: newStatus });
      toast.success("Task status updated");
      fetchData();
    } catch (error: any) {
      toast.error(error.response?.data?.message || "Failed to update status");
    }
  };

  const handleDeleteTask = async () => {
    if (!taskToDelete || !projectId) return;
    if (!permissions.canDeleteTask) {
      toast.error("You don't have permission to delete tasks.");
      return;
    }
    try {
      setIsDeletingTask(true);
      await apiClient.delete(`/tasks/${projectId}/t/${taskToDelete._id}`);
      toast.success("Task deleted successfully");
      setTaskToDelete(null);
      fetchData();
    } catch (error: any) {
      toast.error(error.response?.data?.message || "Failed to delete task");
    } finally {
      setIsDeletingTask(false);
    }
  };

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority) {
      case "high":
        return "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-200";
      case "medium":
        return "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-200";
      default:
        return "bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-200";
    }
  };

  const getColumnConfig = (status: string) => {
    switch (status) {
      case "todo":
        return {
          title: "To Do",
          icon: Circle,
          bgClass: "bg-slate-50/80 dark:bg-slate-900/40",
          borderClass: "border-slate-200/70 dark:border-slate-800/60",
          textClass: "text-slate-600 dark:text-slate-200",
          badgeClass: "bg-slate-200/80 text-slate-700 dark:bg-slate-800 dark:text-slate-200",
        };
      case "in_progress":
        return {
          title: "In Progress",
          icon: AlertCircle,
          bgClass: "bg-amber-50/80 dark:bg-amber-900/20",
          borderClass: "border-amber-200/70 dark:border-amber-800/40",
          textClass: "text-amber-700 dark:text-amber-200",
          badgeClass: "bg-amber-200/80 text-amber-800 dark:bg-amber-800/50 dark:text-amber-100",
        };
      case "done":
        return {
          title: "Done",
          icon: CheckCircle2,
          bgClass: "bg-emerald-50/80 dark:bg-emerald-900/20",
          borderClass: "border-emerald-200/70 dark:border-emerald-800/40",
          textClass: "text-emerald-700 dark:text-emerald-200",
          badgeClass: "bg-emerald-200/80 text-emerald-800 dark:bg-emerald-800/50 dark:text-emerald-100",
        };
      default:
        return {
          title: status,
          icon: Circle,
          bgClass: "bg-slate-100/80 dark:bg-slate-900/40",
          borderClass: "border-slate-200/70 dark:border-slate-800/60",
          textClass: "text-slate-600 dark:text-slate-200",
          badgeClass: "bg-slate-200/80 text-slate-700 dark:bg-slate-800 dark:text-slate-200",
        };
    }
  };

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-96 rounded-2xl border border-muted bg-muted/30 animate-pulse" />
        ))}
      </div>
    );
  }

  if (errorState === "forbidden") {
    return (
      <div className="rounded-2xl border border-amber-200 bg-amber-50 p-6 text-amber-900 dark:border-amber-900/40 dark:bg-amber-900/20 dark:text-amber-100">
        <h2 className="text-xl font-semibold">Access restricted</h2>
        <p className="mt-2 text-sm">
          You don&apos;t have permission to view this project. Contact an admin if you believe this is a mistake.
        </p>
      </div>
    );
  }

  if (errorState === "error") {
    return (
      <div className="rounded-2xl border border-slate-200/70 bg-white/90 p-6 text-slate-700 shadow-sm dark:border-slate-800/70 dark:bg-slate-950/60 dark:text-slate-200">
        <h2 className="text-xl font-semibold">Something went wrong</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          We couldn&apos;t load this project. Please refresh the page or try again later.
        </p>
      </div>
    );
  }

  if (errorState === "not_found" || !project) {
    return (
      <div className="rounded-2xl border border-rose-200 bg-rose-50 p-6 text-rose-900 dark:border-rose-900/40 dark:bg-rose-900/20 dark:text-rose-100">
        <h2 className="text-xl font-semibold">Project not found</h2>
        <p className="mt-2 text-sm">
          The project you&apos;re looking for doesn&apos;t exist or has been removed.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Project Header */}
      <div className="rounded-2xl border border-slate-200/70 bg-white/90 p-6 shadow-sm dark:border-slate-800/70 dark:bg-slate-950/60">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-3xl font-semibold text-slate-900 dark:text-slate-50">{project.name}</h2>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">
                {project.description || "No description provided yet."}
              </p>
              <div className="flex items-center gap-2 mt-3">
                <div className="rounded-full w-7 h-7 bg-gradient-to-br from-sky-500 to-emerald-500 flex items-center justify-center text-white text-xs font-semibold">
                  {project.owner?.username?.[0]?.toUpperCase() || "?"}
                </div>
                <span className="text-sm text-slate-500 dark:text-slate-400">Owner: {project.owner?.username}</span>
              </div>
            </div>
          </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="board" className="w-full">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between mb-4">
          <TabsList>
            <TabsTrigger value="board">Board</TabsTrigger>
            <TabsTrigger value="members">Members</TabsTrigger>
            <TabsTrigger value="notes">Notes</TabsTrigger>
          </TabsList>
          <CreateTaskDialog
            projectId={project._id}
            onTaskCreated={fetchData}
            projectRole={projectRole}
          />
        </div>

        {/* Kanban Board */}
        <TabsContent value="board" className="mt-0">
          <TaskFilters
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            priorityFilter={priorityFilter}
            onPriorityChange={setPriorityFilter}
            assigneeFilter={assigneeFilter}
            onAssigneeChange={setAssigneeFilter}
            assignees={getUniqueAssignees()}
          />
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {["todo", "in_progress", "done"].map((status) => {
              const config = getColumnConfig(status);
              const Icon = config.icon;
              const columnTasks = getTasksByStatus(status);

              return (
                <div
                  key={status}
                  className={`rounded-2xl border ${config.borderClass} ${config.bgClass} shadow-sm min-h-[500px]`}
                >
                  <div className="p-4">
                    {/* Column Header */}
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-2">
                        <Icon className={`w-5 h-5 ${config.textClass}`} />
                        <h3 className={`font-bold ${config.textClass}`}>{config.title}</h3>
                      </div>
                      <div className={`px-2.5 py-1 rounded-full text-xs font-semibold ${config.badgeClass}`}>
                        {columnTasks.length}
                      </div>
                    </div>

                    {/* Task Cards */}
                    <div className="space-y-3 overflow-y-auto">
                      {columnTasks.map((task) => (
                        <div key={task._id} className="rounded-xl border border-slate-200/60 bg-white/90 p-4 shadow-sm transition-shadow hover:shadow-lg dark:border-slate-800/60 dark:bg-slate-950/70">
                            {/* Task Header */}
                            <div className="flex justify-between items-start gap-2">
                              <h4 className="font-semibold text-sm flex-1 line-clamp-2">{task.title}</h4>
                              {showTaskMenu && (
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="h-6 w-6 flex-shrink-0">
                                      <MoreVertical className="h-3 w-3" />
                                    </Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end">
                                    {permissions.canUpdateTask && (
                                      <>
                                        <EditTaskDialog
                                          task={task}
                                          projectId={project._id}
                                          onTaskUpdated={fetchData}
                                          trigger={
                                            <DropdownMenuItem onSelect={(e) => e.preventDefault()}>
                                              Edit Task
                                            </DropdownMenuItem>
                                          }
                                        />
                                        {task.status !== "todo" && (
                                          <DropdownMenuItem onClick={() => handleStatusChange(task._id, "todo")}>
                                            Move to To Do
                                          </DropdownMenuItem>
                                        )}
                                        {task.status !== "in_progress" && (
                                          <DropdownMenuItem onClick={() => handleStatusChange(task._id, "in_progress")}>
                                            Move to In Progress
                                          </DropdownMenuItem>
                                        )}
                                        {task.status !== "done" && (
                                          <DropdownMenuItem onClick={() => handleStatusChange(task._id, "done")}>
                                            Mark as Done
                                          </DropdownMenuItem>
                                        )}
                                      </>
                                    )}
                                    {permissions.canDeleteTask && (
                                      <DropdownMenuItem
                                        className="text-red-600 dark:text-red-400 focus:text-red-600 dark:focus:text-red-400"
                                        onClick={() => setTaskToDelete(task)}
                                      >
                                        <Trash2 className="w-4 h-4 mr-2" />
                                        Delete Task
                                      </DropdownMenuItem>
                                    )}
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              )}
                            </div>

                            {/* Task Description */}
                            <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 mt-2">{task.description}</p>

                            {/* Task Metadata */}
                            <div className="flex flex-wrap gap-2 mt-3">
                              <div className={`px-2 py-0.5 rounded-full text-xs font-semibold ${getPriorityBadgeClass(task.priority)}`}>
                                {task.priority}
                              </div>

                              {task.assignee && (
                                <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
                                  <User className="w-3 h-3" />
                                  <span>{task.assignee.username}</span>
                                </div>
                              )}

                              {task.dueDate && (
                                <>
                                  <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
                                    <Calendar className="w-3 h-3" />
                                    <span>{format(new Date(task.dueDate), "MMM d, yyyy")}</span>
                                  </div>
                                  {(() => {
                                    const dueDateStatus = getDueDateStatus(task.dueDate);
                                    return dueDateStatus && (
                                      <div className={`flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium ${dueDateStatus.badgeClass}`}>
                                        <Clock className="w-3 h-3" />
                                        <span>{dueDateStatus.daysText}</span>
                                      </div>
                                    );
                                  })()}
                                </>
                              )}
                            </div>
                        </div>
                      ))}

                      {/* Empty State */}
                      {columnTasks.length === 0 && (
                        <div className="text-center py-8 text-slate-400 dark:text-slate-500">
                          <Icon className="w-12 h-12 mx-auto mb-2 opacity-30" />
                          <p className="text-sm">No tasks yet</p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </TabsContent>

        {/* Members Tab */}
        <TabsContent value="members">
          <ProjectMembers projectId={project._id} />
        </TabsContent>

        {/* Notes Tab */}
        <TabsContent value="notes">
          <ProjectNotes projectId={project._id} />
        </TabsContent>
      </Tabs>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!taskToDelete} onOpenChange={(open) => !open && setTaskToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Task?</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete <strong>"{taskToDelete?.title}"</strong>? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction 
              onClick={handleDeleteTask}
              disabled={isDeletingTask}
              className="bg-red-600 hover:bg-red-700 text-white"
            >
              {isDeletingTask ? "Deleting..." : "Delete Task"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
