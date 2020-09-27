const nodemailer = require("nodemailer");


let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "service.email.ischekoldin@gmail.com",
        pass: "Timbnvp1!"
    }
});

module.exports = async function sendVerificationEmail (mailTarget, token) {

    console.log(mailTarget, token);
    const verificationLink = `https://telecom-dashboard-server.herokuapp.com/email/verify?token=${token}`;

    const mailOptions = {
         from: "service.email.ischekoldin@gmail.com",
         to: mailTarget,
         subject: "Telecom Dashboard - Email Confirmation",
         text: `Подтвердите свой адрес email, перейдя по ссылке ${verificationLink}`
    };


    await transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            return err;
        } else {
            return info;
        }
    })
};

