import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { ErrorCodes } from "../utils/error-codes.js";
import { asyncHandler } from "../utils/async-handler.js";
import { buildFrontendUrl } from "../utils/url.js";
import {
  registerUser as registerUserService,
  loginUser as loginUserService,
  verifyEmailToken,
  resendEmailVerification as resendEmailVerificationService,
  refreshTokens,
  requestPasswordReset,
  resetForgotPassword as resetForgotPasswordService,
  changePassword,
} from "../services/auth.service.js";
import {
  sendPasswordResetEmail,
  sendVerificationEmail,
} from "../services/email.service.js";

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, fullName } = req.body;

  const { user, verificationToken } = await registerUserService({
    email,
    username,
    password,
    fullName,
  });

  const verificationUrl = buildFrontendUrl(
    `/verify-email/${verificationToken}`,
    req,
  );
  await sendVerificationEmail({ user, verificationUrl });

  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        { user },
        "User registered successfully. Verification email has been sent.",
      ),
    );
});

const login = asyncHandler(async (req, res) => {
  const { email, password, username } = req.body;
  const identifier = email || username;

  if (!identifier) {
    throw new ApiError(400, "Email or username is required", ErrorCodes.INVALID_REQUEST);
  }

  const { user, accessToken, refreshToken } = await loginUserService({
    identifier,
    password,
  });

  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        {
          user,
          accessToken,
          refreshToken,
        },
        "User logged in successfully",
      ),
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await req.user?.updateOne({
    $set: {
      refreshToken: "",
    },
  });

  return res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user fetched successfully"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;
  const data = await verifyEmailToken(verificationToken);

  return res
    .status(200)
    .json(new ApiResponse(200, data, "Email is verified"));
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new ApiError(400, "Email is required", ErrorCodes.INVALID_REQUEST);
  }

  const { user, verificationToken } =
    await resendEmailVerificationService(email);

  const verificationUrl = buildFrontendUrl(
    `/verify-email/${verificationToken}`,
    req,
  );
  await sendVerificationEmail({ user, verificationUrl });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Verification email sent"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  const { accessToken, refreshToken } = await refreshTokens(
    incomingRefreshToken,
  );

  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        { accessToken, refreshToken },
        "Access token refreshed",
      ),
    );
});

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const result = await requestPasswordReset(email);
  if (result?.user) {
    const resetUrl = buildFrontendUrl(
      `/reset-password/${result.resetToken}`,
      req,
    );
    await sendPasswordResetEmail({ user: result.user, resetUrl });
  }

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "If an account exists for that email, a reset link has been sent.",
      ),
    );
});

const resetForgotPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  await resetForgotPasswordService({ resetToken, newPassword });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password reset successfully"));
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  await changePassword({
    userId: req.user?._id,
    oldPassword,
    newPassword,
  });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

export {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgotPassword,
  changeCurrentPassword,
};
