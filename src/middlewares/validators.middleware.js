import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";
import { ErrorCodes } from "../utils/error-codes.js";

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();
  const extractedErrors = errors.array().map((err) => ({
    field: err.path,
    message: err.msg,
  }));

  throw new ApiError(
    422,
    "Received data is not valid",
    ErrorCodes.VALIDATION_ERROR,
    extractedErrors,
  );
};
