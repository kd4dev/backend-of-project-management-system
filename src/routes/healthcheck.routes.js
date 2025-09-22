import { Router } from "express";
import { healthCheck } from "../controllers/healthcheck.controllers.js";
import { asyncHandler } from "../utils/async-handler.js";

const router = Router();

router.route("/").get(healthCheck);

export default router;
