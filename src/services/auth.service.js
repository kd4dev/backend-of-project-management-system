import jwt from "jsonwebtoken";
import crypto from "crypto";
import { User } from "../models/user.models.js";
import { ApiError } from "../utils/api-error.js";
import { ErrorCodes } from "../utils/error-codes.js";

const sanitizeUser = async (userId) => {
  return User.findById(userId).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry",
  );
};

export const generateAccessTokenAndRefreshToken = async (userId) => {
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found", ErrorCodes.USER_NOT_FOUND);
  }

  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  user.refreshToken = refreshToken;
  await user.save({ validateBeforeSave: false });

  return { accessToken, refreshToken };
};

export const registerUser = async ({ email, username, password, fullName }) => {
  const normalizedEmail = email.toLowerCase().trim();
  const normalizedUsername = username.toLowerCase().trim();

  const existingUser = await User.findOne({
    $or: [{ email: normalizedEmail }, { username: normalizedUsername }],
  });

  if (existingUser) {
    if (existingUser.email === normalizedEmail) {
      throw new ApiError(
        409,
        "User with this email already exists",
        ErrorCodes.DUPLICATE_EMAIL,
      );
    }
    if (existingUser.username === normalizedUsername) {
      throw new ApiError(
        409,
        "User with this username already exists",
        ErrorCodes.DUPLICATE_USERNAME,
      );
    }
  }

  const user = await User.create({
    email: normalizedEmail,
    password,
    username: normalizedUsername,
    fullName,
    role: "member",
    isEmailVerified: false,
  });

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;
  await user.save({ validateBeforeSave: false });

  const createdUser = await sanitizeUser(user._id);
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering a user", ErrorCodes.INTERNAL_SERVER_ERROR);
  }

  return { user: createdUser, verificationToken: unhashedToken };
};

const resolveUserByIdentifier = async (identifier) => {
  const normalized = identifier.toLowerCase().trim();
  const query = normalized.includes("@")
    ? { email: normalized }
    : { username: normalized };

  return User.findOne(query);
};

export const loginUser = async ({ identifier, password }) => {
  const user = await resolveUserByIdentifier(identifier);

  if (!user) {
    throw new ApiError(404, "No account found with this email or username", ErrorCodes.USER_NOT_FOUND);
  }

  if (!user.isEmailVerified) {
    throw new ApiError(
      403,
      "Please verify your email before logging in. Check your inbox for the verification link.",
      ErrorCodes.EMAIL_NOT_VERIFIED,
    );
  }

  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "The password you entered is incorrect", ErrorCodes.INVALID_PASSWORD);
  }

  const { accessToken, refreshToken } =
    await generateAccessTokenAndRefreshToken(user._id);

  const loggedInUser = await sanitizeUser(user._id);

  return { user: loggedInUser, accessToken, refreshToken };
};

export const verifyEmailToken = async (verificationToken) => {
  if (!verificationToken) {
    throw new ApiError(400, "Email verification token is missing", ErrorCodes.INVALID_REQUEST);
  }

  const hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(400, "Token is invalid or expired", ErrorCodes.TOKEN_INVALID);
  }

  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;
  user.isEmailVerified = true;
  await user.save({ validateBeforeSave: false });

  return { isEmailVerified: true };
};

export const resendEmailVerification = async (email) => {
  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });

  if (!user) {
    throw new ApiError(404, "User does not exist", ErrorCodes.USER_NOT_FOUND);
  }
  if (user.isEmailVerified) {
    throw new ApiError(409, "User is already verified", ErrorCodes.INVALID_REQUEST);
  }

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  return { user, verificationToken: unhashedToken };
};

export const refreshTokens = async (incomingRefreshToken) => {
  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorised access", ErrorCodes.UNAUTHORIZED);
  }

  let decodedToken;
  try {
    decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    );
  } catch (error) {
    throw new ApiError(401, "Invalid refresh token", ErrorCodes.TOKEN_INVALID);
  }

  const user = await User.findById(decodedToken?._id);
  if (!user) throw new ApiError(401, "Invalid refresh token", ErrorCodes.TOKEN_INVALID);
  if (incomingRefreshToken !== user?.refreshToken) {
    throw new ApiError(401, "Refresh token is expired", ErrorCodes.TOKEN_EXPIRED);
  }

  const { accessToken, refreshToken: newRefreshToken } =
    await generateAccessTokenAndRefreshToken(user._id);

  user.refreshToken = newRefreshToken;
  await user.save({ validateBeforeSave: false });

  return { accessToken, refreshToken: newRefreshToken };
};

export const requestPasswordReset = async (email) => {
  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) return null;

  const { unhashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  return { user, resetToken: unhashedToken };
};

export const resetForgotPassword = async ({ resetToken, newPassword }) => {
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  const user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });
  if (!user) throw new ApiError(400, "Token is invalid or expired", ErrorCodes.TOKEN_INVALID);

  user.forgotPasswordExpiry = undefined;
  user.forgotPasswordToken = undefined;
  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return true;
};

export const changePassword = async ({ userId, oldPassword, newPassword }) => {
  const user = await User.findById(userId);
  if (!user) throw new ApiError(404, "User not found", ErrorCodes.USER_NOT_FOUND);

  const isPasswordValid = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordValid) {
    throw new ApiError(400, "Invalid old password", ErrorCodes.INVALID_PASSWORD);
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return true;
};
