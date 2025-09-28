import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

export const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();
  const extractedErrors = [];
  errors.array().map((err) => extractedErrors.push(
    {
        [err.path]: err.msg
    }));
     //ye .array() se 100% confirm kiya ki ye array hi he,ye generally array hi hota he par na ho toh convert kar

    throw new ApiError(422,"Recieved data is not valid",extractedErrors)
};
