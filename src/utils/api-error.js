class ApiError extends Error {
  constructor(
    statusCode,
    message = "Something went wrong",
    errorCode = "INTERNAL_SERVER_ERROR",
    errors = [],
    stack = "",
  ) {
    super(message); //calling constructor of parent class
    this.statusCode = statusCode;
    this.message = message;
    this.success = false;
    this.errorCode = errorCode;
    this.errors = errors;
    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export { ApiError };
