import "dotenv/config";
import Mailgen from "mailgen";
import nodemailer from "nodemailer";
import { ApiError } from "./api-error.js";

const sendEmail=async function(options){
    const mailGenerator=new Mailgen({
        theme:"default",
        product:{
            name: "Task Manager",
            link: "https://taskmanagelink.com"
        }
    })
    const emailTextual=mailGenerator.generatePlaintext(options.mailgenContent)
    const emailHtml=mailGenerator.generate(options.mailgenContent) 

    const transporter=nodemailer.createTransport({
        host : process.env.MAIL_SMTP_HOST,
        port:process.env.MAIL_SMTP_PORT,
        auth:{
            user:process.env.MAIL_SMTP_USER,
            pass:process.env.MAIL_SMTP_PASS
        }
    })

    const mail={
        from: "mail.taskmanager@example.com",
        to: options.email,
        subject: options.subject,
        text: emailTextual,
        html: emailHtml
    }

    try {
        await transporter.sendMail(mail)

    } catch (error) {
        console.error("Email service failed silently.Make sure that you have provided your MAILTRAP credentials in the .env file",);
        throw new ApiError(400,`Error:${error}`)
    }
}

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