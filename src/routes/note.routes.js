import express from "express";
import { verifyJWT, requireGlobalRole, attachProject } from "../middlewares/auth.middleware.js";
import {
    getProjectNotes,
    createNote,
    getNoteDetails,
    updateNote,
    deleteNote
} from "../controllers/note.controllers.js";

const router = express.Router();

router.use(verifyJWT);
router.use("/:projectId", attachProject);

router.route("/:projectId")
    .get(getProjectNotes)
    .post(requireGlobalRole(["admin"]), createNote);

router.route("/:projectId/n/:noteId")
    .get(getNoteDetails)
    .put(requireGlobalRole(["admin"]), updateNote)
    .delete(requireGlobalRole(["admin"]), deleteNote);

export default router;
