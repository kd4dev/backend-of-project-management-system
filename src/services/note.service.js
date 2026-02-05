import { Note } from "../models/note.models.js";
import { ApiError } from "../utils/api-error.js";
import { ErrorCodes } from "../utils/error-codes.js";

export const getProjectNotes = async (projectId) => {
  return Note.find({ project: projectId }).populate(
    "author",
    "username fullName",
  );
};

export const createNote = async ({ projectId, authorId, content }) => {
  if (!content) {
    throw new ApiError(400, "Note content is required", ErrorCodes.VALIDATION_ERROR);
  }

  const note = await Note.create({
    content,
    project: projectId,
    author: authorId,
  });

  return note;
};

export const getNoteDetails = async ({ projectId, noteId }) => {
  const note = await Note.findOne({ _id: noteId, project: projectId }).populate(
    "author",
    "username fullName",
  );
  if (!note) throw new ApiError(404, "Note not found", ErrorCodes.NOTE_NOT_FOUND);

  return note;
};

export const updateNote = async ({ projectId, noteId, content }) => {
  const note = await Note.findOneAndUpdate(
    { _id: noteId, project: projectId },
    { content },
    { new: true, runValidators: true },
  );

  if (!note) throw new ApiError(404, "Note not found", ErrorCodes.NOTE_NOT_FOUND);

  return note;
};

export const deleteNote = async ({ projectId, noteId }) => {
  const note = await Note.findOneAndDelete({ _id: noteId, project: projectId });
  if (!note) throw new ApiError(404, "Note not found", ErrorCodes.NOTE_NOT_FOUND);

  return true;
};
