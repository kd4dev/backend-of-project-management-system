import { useEffect, useState } from "react";
import apiClient from "@/api/client";
import { AddMemberDialog } from "./AddMemberDialog";
import { useAuth } from "@/context/AuthContext";
import { getPermissions, getRoleDisplayName } from "@/lib/permissions";
import { UserMinus, Mail, Shield } from "lucide-react";
import { toast } from "sonner";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
 AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";

interface Member {
  _id: string;
  user: {
    _id: string;
    username: string;
    fullName?: string;
    email: string;
    avatar?: { url: string };
  };
  role: string;
}

export function ProjectMembers({ projectId }: { projectId: string }) {
  const [members, setMembers] = useState<Member[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [memberToRemove, setMemberToRemove] = useState<Member | null>(null);
  const { user } = useAuth();
  const permissions = getPermissions(user?.role);

  useEffect(() => {
    fetchMembers();
  }, [projectId]);

  const fetchMembers = async () => {
    try {
      setIsLoading(true);
      const response = await apiClient.get(`/projects/${projectId}/members`);
      setMembers(response.data.data);
    } catch (error) {
      console.error(error);
      toast.error("Failed to load members");
    } finally {
      setIsLoading(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: string) => {
    try {
      await apiClient.put(`/projects/${projectId}/members/${userId}`, { role: newRole });
      toast.success("Member role updated successfully");
      fetchMembers();
    } catch (error: any) {
      toast.error(error.response?.data?.message || "Failed to update role");
    }
  };

  const handleRemoveMember = async () => {
    if (!memberToRemove) return;
    
    try {
      await apiClient.delete(`/projects/${projectId}/members/${memberToRemove.user._id}`);
      toast.success("Member removed successfully");
      setMemberToRemove(null);
      fetchMembers();
    } catch (error: any) {
      toast.error(error.response?.data?.message || "Failed to remove member");
    }
  };

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-32 w-full rounded-2xl border border-muted bg-muted/30 animate-pulse"></div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h3 className="text-2xl font-bold">Team Members</h3>
          <p className="text-base-content/70 mt-1">Manage project team and roles</p>
        </div>
        {permissions.canManageMembers && <AddMemberDialog projectId={projectId} onMemberAdded={fetchMembers} />}
      </div>

      {/* Member Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {members.map((member) => (
          <div
            key={member.user._id}
            className="rounded-2xl border border-slate-200/70 bg-white/90 p-6 shadow-sm transition-shadow hover:shadow-lg dark:border-slate-800/70 dark:bg-slate-950/60"
          >
              {/* Member Info */}
              <div className="flex items-start gap-4 mb-4">
                <div className="avatar placeholder">
                  <div className="rounded-full w-14 h-14 bg-gradient-to-br from-sky-500 to-emerald-500 flex items-center justify-center text-white">
                    <span className="text-xl font-bold">{member.user.username[0]?.toUpperCase() || "?"}</span>
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <h4 className="font-bold truncate text-lg">{member.user.fullName || member.user.username}</h4>
                  <div className="flex items-center gap-1 text-sm text-base-content/60 mt-1">
                    <Mail className="w-3 h-3" />
                    <span className="truncate">{member.user.email}</span>
                  </div>
                </div>
              </div>

              {/* Role Management */}
              <div className="flex items-center justify-between gap-3 mt-auto">
                {permissions.canManageMembers ? (
                  <div className="flex-1">
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400">Role</label>
                    <Select value={member.role} onValueChange={(value) => handleRoleChange(member.user._id, value)}>
                      <SelectTrigger className="w-full">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="manager">
                          <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 text-warning" />
                            <span>Manager</span>
                          </div>
                        </SelectItem>
                        <SelectItem value="member">
                          <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 text-info" />
                            <span>Member</span>
                          </div>
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                ) : (
                  <div className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                    {getRoleDisplayName(member.role)}
                  </div>
                )}

                {/* Remove Button */}
                {permissions.canManageMembers && member.user._id !== user?._id && (
                  <AlertDialog open={memberToRemove?.user._id === member.user._id} onOpenChange={(open) => !open && setMemberToRemove(null)}>
                    <AlertDialogTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="rounded-full"
                        onClick={() => setMemberToRemove(member)}
                      >
                        <UserMinus className="h-4 w-4 text-rose-500" />
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>Remove Team Member?</AlertDialogTitle>
                        <AlertDialogDescription>
                          Are you sure you want to remove <strong>{member.user.username}</strong> from this project? This action cannot be undone.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction onClick={handleRemoveMember} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                          Remove
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                )}
              </div>
            </div>

        ))}
      </div>

      {/* Empty State */}
      {members.length === 0 && (
        <div className="rounded-2xl border border-dashed border-slate-200/70 bg-white/70 p-10 text-center dark:border-slate-800/70 dark:bg-slate-950/40">
          <Shield className="w-16 h-16 mx-auto text-slate-300 dark:text-slate-600" />
          <h3 className="text-2xl font-bold mt-4">No team members yet</h3>
          <p className="py-4 text-muted-foreground">
            {permissions.canManageMembers
              ? "Add team members to collaborate on this project."
              : "No members have been added to this project yet."}
          </p>
        </div>
      )}
    </div>
  );
}
