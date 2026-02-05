import {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendEmail,
} from "../utils/mail.js";

export const sendVerificationEmail = async ({ user, verificationUrl }) => {
  await sendEmail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(user.username, verificationUrl),
  });
};

export const sendPasswordResetEmail = async ({ user, resetUrl }) => {
  await sendEmail({
    email: user.email,
    subject: "Reset your password",
    mailgenContent: forgotPasswordMailgenContent(user.username, resetUrl),
  });
};
