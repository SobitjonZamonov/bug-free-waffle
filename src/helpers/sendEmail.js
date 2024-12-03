import nodemailer from 'nodemailer';
import { email } from '../config/index.config.js';

const transporter = nodemailer.createTransport({
    service: 'gmail',
    secure: false,
    auth: {
        user: process.env.USER_EMAIL,
        pass: process.env.APP_PASSWORD
    },
});

export const sendMail = async (to, subject, html) => {
    try {
        const info = await transporter.sendMail({
            from: email.user,
            to,
            subject,
            html,
        });
        console.log('Email sent: ' + info.response);
    } catch (error) {
        console.error('Error sending email: ', error);
    }
};
