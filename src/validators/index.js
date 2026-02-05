import { body } from "express-validator";
import { PASSWORD_REGEX, PASSWORD_REQUIREMENTS_MESSAGE } from "../utils/password.js";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("Username must be in lower case")
      .isLength({ min: 3 })
      .withMessage("Username must have at least 3 characters"),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .matches(PASSWORD_REGEX)
      .withMessage(PASSWORD_REQUIREMENTS_MESSAGE),
    body("fullName").optional().trim(),
  ];
};

const userLoginValidator = () => {
  return [
    body("email")
      .custom((value, { req }) => {
        if (!value && !req.body.username) {
          throw new Error("Email or username is required");
        }
        return true;
      })
      .optional()
      .trim(),
    body("username").optional().trim(),
    body("password").trim().notEmpty().withMessage("Password is required"),
  ];
};

const userChangeCurrentPasswordValidator = () => {
  return[
    body("oldPassword")
      .notEmpty()
      .withMessage("Old Password is required"),
    body("newPassword")
      .notEmpty()
      .withMessage("New Password is required")
      .matches(PASSWORD_REGEX)
      .withMessage(PASSWORD_REQUIREMENTS_MESSAGE)
  ]
}

const userForgotPasswordValidator = () => {
  return[
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),

  ]
}

const userResendEmailVerificationValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
  ];
};

const userResetForgotPasswordValidator=()=>{
  return[
    body("newPassword")
      .notEmpty()
      .withMessage("Password is required")
      .matches(PASSWORD_REGEX)
      .withMessage(PASSWORD_REQUIREMENTS_MESSAGE)
  ]
}

export { 
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
  userResendEmailVerificationValidator,
};
