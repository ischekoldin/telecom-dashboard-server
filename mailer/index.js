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
    const verificationLink = `href=http://localhost:5000/email/verify?token=${token}`;

    const mailOptions = {
         from: "service.email.ischekoldin@gmail.com",
         to: mailTarget,
         subject: "Telecom Dashboard - Email Confirmation",
         text: `Подтвердите свой адрес email, перейдя по ссылке ${verificationLink}`
    };


    await transporter.sendMail(mailOptions, (err, info) => {
        console.log(mailOptions);
        if (err) {
            console.log(err);
            return err
        } else {
            console.log(info);
            return info
        }
    })
};

