import { ErrorCodes } from "../utils/error-codes.js";

export const errorHandler = (err, req, res, next) => {
  let statusCode = err.statusCode || 500;
  let errorCode = err.errorCode || ErrorCodes.INTERNAL_SERVER_ERROR;
  let message = err.message || "Internal server error";
  let errors = Array.isArray(err.errors) ? err.errors : [];

  if (err.name === "ValidationError") {
    statusCode = 400;
    errorCode = ErrorCodes.VALIDATION_ERROR;
    message = "Validation failed";
    errors = Object.values(err.errors || {}).map((errorItem) => ({
      field: errorItem.path,
      message: errorItem.message,
    }));
  }

  if (err.code === 11000) {
    statusCode = 409;
    errorCode = ErrorCodes.INVALID_REQUEST;
    const duplicateField = Object.keys(err.keyPattern || {})[0];
    message = duplicateField
      ? `Duplicate value for ${duplicateField}`
      : "Duplicate value";
    errors = duplicateField
      ? [{ field: duplicateField, message }]
      : errors;
  }

  if (err.name === "CastError") {
    statusCode = 400;
    errorCode = ErrorCodes.INVALID_REQUEST;
    message = "Invalid identifier provided";
  }

  const payload = {
    success: false,
    errorCode,
    message,
    errors,
  };

  if (process.env.NODE_ENV !== "production" && err.stack) {
    payload.stack = err.stack;
  }

  res.status(statusCode).json(payload);
};
