import { useEffect, useState } from "react";
import apiClient from "@/api/client";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";
import { getPermissions } from "@/lib/permissions";
import { FileText, Plus, User, Calendar } from "lucide-react";
import { format } from "date-fns";

interface Note {
  _id: string;
  content: string;
  author: { username: string };
  createdAt: string;
  updatedAt: string;
}

export function ProjectNotes({ projectId }: { projectId: string }) {
  const [notes, setNotes] = useState<Note[]>([]);
  const [newNote, setNewNote] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { user } = useAuth();
  const permissions = getPermissions(user?.role);

  useEffect(() => {
    fetchNotes();
  }, [projectId]);

  const fetchNotes = async () => {
    try {
      setIsLoading(true);
      const response = await apiClient.get(`/notes/${projectId}`);
      // Sort notes by createdAt descending (most recent first)
      const sortedNotes = response.data.data.sort(
        (a: Note, b: Note) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
      setNotes(sortedNotes);
    } catch (error) {
      console.error(error);
      toast.error("Failed to load notes");
    } finally {
      setIsLoading(false);
    }
  };

  const createNote = async () => {
    if (!newNote.trim()) {
      toast.error("Note content cannot be empty");
      return;
    }
    setIsSubmitting(true);
    try {
      await apiClient.post(`/notes/${projectId}`, { content: newNote });
      toast.success("Note added successfully");
      setNewNote("");
      fetchNotes();
    } catch (error: any) {
      const errorMessage = error.response?.data?.message || "Failed to add note";
      toast.error(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-32 w-full rounded-2xl border border-muted bg-muted/30 animate-pulse"></div>
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h3 className="text-2xl font-bold">Project Notes</h3>
        <p className="text-base-content/70 mt-1">
          {permissions.canCreateNote
            ? "Document important information and decisions"
            : "View project notes and updates"}
        </p>
      </div>

      {/* Create Note (Admin Only) */}
      {permissions.canCreateNote && (
        <div className="rounded-2xl border border-slate-200/70 bg-white/90 p-6 shadow-sm dark:border-slate-800/70 dark:bg-slate-950/60">
            <h4 className="text-lg font-semibold">Add New Note</h4>
            <textarea
              className="mt-3 w-full min-h-[120px] rounded-xl border border-slate-200/70 bg-white px-3 py-2 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-sky-500 dark:border-slate-800/70 dark:bg-slate-900"
              placeholder="Write your note here... Share updates, decisions, or important information about the project."
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              maxLength={5000}
            />
            <div className="flex justify-between items-center mt-2">
              <span className="text-sm text-base-content/50">{newNote.length}/5000 characters</span>
              <button
                onClick={createNote}
                disabled={isSubmitting || !newNote.trim()}
                className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-sky-700 disabled:cursor-not-allowed disabled:bg-slate-300"
              >
                {isSubmitting ? (
                  <>
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white"></span>
                    Adding...
                  </>
                ) : (
                  <>
                    <Plus className="w-4 h-4" />
                    Add Note
                  </>
                )}
              </button>
            </div>
        </div>
      )}

      {/* Notes List */}
      <div className="space-y-4">
        {notes.map((note) => (
          <div
            key={note._id}
            className="rounded-2xl border border-slate-200/70 bg-white/90 p-6 shadow-sm transition-shadow hover:shadow-lg dark:border-slate-800/70 dark:bg-slate-950/60"
          >
              {/* Note Header */}
              <div className="flex justify-between items-start gap-4 mb-3">
                <div className="flex items-center gap-3">
                  <div className="avatar placeholder">
                    <div className="rounded-full w-10 h-10 bg-gradient-to-br from-sky-500 to-emerald-500 flex items-center justify-center text-white">
                      <span className="text-sm font-semibold">{note.author.username[0]?.toUpperCase() || "?"}</span>
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <User className="w-4 h-4 text-base-content/50" />
                      <span className="font-semibold">{note.author.username}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-base-content/50 mt-1">
                      <Calendar className="w-3 h-3" />
                      <span>{format(new Date(note.createdAt), "MMM d, yyyy 'at' h:mm a")}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Note Content */}
              <div className="prose max-w-none">
                <p className="whitespace-pre-wrap text-base-content/90">{note.content}</p>
              </div>

              {/* Updated Indicator */}
              {note.updatedAt !== note.createdAt && (
                <div className="text-xs text-base-content/40 mt-2">Edited {format(new Date(note.updatedAt), "MMM d, yyyy")}</div>
              )}
          </div>
        ))}

        {/* Empty State */}
        {notes.length === 0 && (
          <div className="rounded-2xl border border-dashed border-slate-200/70 bg-white/70 p-10 text-center dark:border-slate-800/70 dark:bg-slate-950/40">
            <FileText className="w-16 h-16 mx-auto text-slate-300 dark:text-slate-600" />
            <h3 className="text-2xl font-bold mt-4">No notes yet</h3>
            <p className="py-4 text-muted-foreground">
              {permissions.canCreateNote
                ? "Start documenting important information by creating your first note."
                : "No notes have been added to this project yet."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
