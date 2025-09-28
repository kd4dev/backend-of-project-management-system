import { body } from "express-validator";

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
    body("password").trim().notEmpty().withMessage("Password is required"),
    body("fullName").optional().trim(),
  ];
};

const userLoginValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
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

const userResetForgotPasswordValidator=()=>{
  return[
    body("newPassword")
    .notEmpty()
    .withMessage("Password is required")
  ]
}

export { userRegisterValidator, userLoginValidator, userChangeCurrentPasswordValidator, userForgotPasswordValidator,userResetForgotPasswordValidator };
