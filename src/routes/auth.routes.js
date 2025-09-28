import express from "express";
import {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgotPassword,
  changeCurrentPassword,
  resendEmailVerification,
} from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validators.middleware.js";
import {
  userRegisterValidator,
  userLoginValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
  userChangeCurrentPasswordValidator,
} from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = express.Router();

//Unsecure routes-->anyone can access
//router.post('/register',userRegisterValidator(),validate,registerUser);
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post(userForgotPasswordValidator(),validate,forgotPasswordRequest);
router.route("/reset-password/:resetToken").post(userResetForgotPasswordValidator(),validate,resetForgotPassword)

//secure routes-->these routes require jwt
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/current-user").get(verifyJWT, getCurrentUser);
router.route("/change-password/").post(verifyJWT,userChangeCurrentPasswordValidator(),validate,changeCurrentPassword);;
router.route("/resend-email-verification").post(verifyJWT,resendEmailVerification);

export default router;
