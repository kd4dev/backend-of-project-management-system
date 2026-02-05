import { ApiResponse } from "../utils/api-response.js";
import { asyncHandler } from "../utils/async-handler.js";
import {
  createNote as createNoteService,
  deleteNote as deleteNoteService,
  getNoteDetails as getNoteDetailsService,
  getProjectNotes as getProjectNotesService,
  updateNote as updateNoteService,
} from "../services/note.service.js";

const getProjectNotes = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const notes = await getProjectNotesService(projectId);

  return res
    .status(200)
    .json(new ApiResponse(200, notes, "Notes fetched"));
});

const createNote = asyncHandler(async (req, res) => {
  const { projectId } = req.params;
  const { content } = req.body;

  const note = await createNoteService({
    projectId,
    authorId: req.user._id,
    content,
  });

  return res
    .status(201)
    .json(new ApiResponse(201, note, "Note created"));
});

const getNoteDetails = asyncHandler(async (req, res) => {
  const { projectId, noteId } = req.params;
  const note = await getNoteDetailsService({ projectId, noteId });

  return res
    .status(200)
    .json(new ApiResponse(200, note, "Note details fetched"));
});

const updateNote = asyncHandler(async (req, res) => {
  const { projectId, noteId } = req.params;
  const { content } = req.body;

  const note = await updateNoteService({ projectId, noteId, content });

  return res
    .status(200)
    .json(new ApiResponse(200, note, "Note updated"));
});

const deleteNote = asyncHandler(async (req, res) => {
  const { projectId, noteId } = req.params;
  await deleteNoteService({ projectId, noteId });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Note deleted"));
});

export {
  getProjectNotes,
  createNote,
  getNoteDetails,
  updateNote,
  deleteNote,
};
