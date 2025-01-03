import nodemailer from 'nodemailer';
import env from './env.js';

const transporter = nodemailer.createTransport({
    host: 'smtp.office365.com',
    secureConnection: true,
    port: 587,
    auth: {
        user: env.SMTP_EMAIL,
        pass: env.SMTP_PASSWORD
    },
} as any);

// Function to send email
export async function sendEmail(
    to: string,
    title: string,
    text: string,
    html: string
) {
    const mailOptions = {
        from: '"osu!uwaterloo" <osu@clubs.wusa.ca>',
        to: to,
        subject: title,
        text: text,
        html: html,
    };

    const info = await transporter.sendMail(mailOptions);

    console.log(`Email sent to ${to}: ${info.messageId}`);

    return info;
}