import "dotenv/config";
import Mailgen from "mailgen";
import nodemailer from "nodemailer";
import { ApiError } from "./api-error.js";
import { ErrorCodes } from "./error-codes.js";

const resolveTransportConfig = () => {
  const isProduction = process.env.NODE_ENV === "production";

  if (isProduction) {
    return {
      host: process.env.MAIL_SMTP_HOST,
      port: Number(process.env.MAIL_SMTP_PORT || 587),
      secure: Number(process.env.MAIL_SMTP_PORT) === 465,
      auth: {
        user: process.env.MAIL_SMTP_USER,
        pass: process.env.MAIL_SMTP_PASS,
      },
    };
  }

  return {
    host: process.env.MAILTRAP_HOST || process.env.MAIL_SMTP_HOST,
    port: Number(process.env.MAILTRAP_PORT || process.env.MAIL_SMTP_PORT || 2525),
    secure: false,
    auth: {
      user: process.env.MAILTRAP_USER || process.env.MAIL_SMTP_USER,
      pass: process.env.MAILTRAP_PASS || process.env.MAIL_SMTP_PASS,
    },
  };
};

const sendEmail = async function (options) {
  const mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: process.env.MAIL_PRODUCT_NAME || "Task Manager",
      link: process.env.MAIL_PRODUCT_LINK || "https://taskmanagelink.com",
    },
  });
  const emailTextual = mailGenerator.generatePlaintext(options.mailgenContent);
  const emailHtml = mailGenerator.generate(options.mailgenContent);

  const transportConfig = resolveTransportConfig();
  if (!transportConfig.host || !transportConfig.auth?.user || !transportConfig.auth?.pass) {
    throw new ApiError(
      500,
      "Email transport is not configured",
      ErrorCodes.EMAIL_SEND_FAILED,
    );
  }

  const transporter = nodemailer.createTransport(transportConfig);

  const mail = {
    from: process.env.MAIL_FROM || "Task Manager <no-reply@taskmanager.com>",
    to: options.email,
    subject: options.subject,
    text: emailTextual,
    html: emailHtml,
  };

  try {
    await transporter.sendMail(mail);
  } catch (error) {
    console.error("Email service failed:", error);
    throw new ApiError(500, "Failed to send email", ErrorCodes.EMAIL_SEND_FAILED);
  }
};

const emailVerificationMailgenContent=(username,verificationUrl)=>{
    return {
        body: {
            name: username,
            intro: "Welcome to our App! We're excited to have you on board.",
            action: {
                instructions: "To verify your email please click on the following button",
                button: {
                    color: '#22BC66', 
                    text: "Verify your email",
                    link: verificationUrl
                }
            },
            outro: "Need help, or have questions? Just reply to this email, we'd love to help."
        },
    }
}

const forgotPasswordMailgenContent=(username,passwordResetUrl)=>{
    return {
        body: {
            name: username,
            intro: "We got a request to reset password",
            action: {
                instructions: "To reset your password please click on the following button or link",
                button: {
                    color: '#22BC66', 
                    text: "ResetPassword",
                    link: passwordResetUrl
                }
            },
            outro: "Need help, or have questions? Just reply to this email, we'd love to help."
        },
    }
}

export {emailVerificationMailgenContent,forgotPasswordMailgenContent,sendEmail};
