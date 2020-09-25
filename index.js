require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require("bcrypt");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const utils = require("./utils/utils");


const app = express();

const router = require('./router');
const pool = require('./db/index');

const sendVerificationEmail = require("./mailer/index.js");

const json_dummy_user = require("./db/user");



app.use(router);

const CORS_OPTIONS = {
    origin: process.env.FRONTEND_HOST,
    credentials: true,
    preflightContinue: true
};

console.log(CORS_OPTIONS);

const USER_EMAIL_COOKIE_OPTIONS = { expires: utils.cookieExpiresIn(14), httpOnly: false, sameSite: "none", secure: true};

let REFRESH_TOKEN_COOKIE_OPTIONS;

if (!process.env.NODE_ENV || process.env.NODE_ENV === 'development') {
    REFRESH_TOKEN_COOKIE_OPTIONS = { expires: utils.cookieExpiresIn(14), httpOnly: true, sameSite: "lax"};
} else {
    REFRESH_TOKEN_COOKIE_OPTIONS = { expires: utils.cookieExpiresIn(14), httpOnly: true, sameSite: "none", secure: true};
}

// middleware
app.use(cors(CORS_OPTIONS));
app.use(express.json());
app.use(cookieParser());


let errors = [];


function generateAccessToken(user) {
    console.log(user);
    const TOKEN_EXPIRATION_TIME = '15m';
    return  jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: TOKEN_EXPIRATION_TIME });
}


function generateEmailVerificationToken(email) {
    const TOKEN_EXPIRATION_TIME = '15m';
    return  jwt.sign(email, process.env.EMAIL_VERIFICATION_SECRET, { expiresIn: TOKEN_EXPIRATION_TIME });
}


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    })
}


function authenticateEmailToken(req, res, next) {
    const token = req.query.token;
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.EMAIL_VERIFICATION_SECRET, (err, email) => {
        if (err) return res.sendStatus(403);
        req.email = email;
        next();
    })
}


async function checkPassword (email, password) {
    try {
        const dbResponse = await pool.query("SELECT * FROM users WHERE user_email = $1", [email]);
        const numberOfUsers = dbResponse.rowCount;

        if (numberOfUsers === 1) {
            const hashedPassword = dbResponse.rows[0].user_password;
            const isPasswordCorrect = await bcrypt.compare(password, hashedPassword);

            if (isPasswordCorrect) {
                return 'password is correct'
            } else {
                return new Error('password is incorrect')
            }

        } else {
            return new Error('user not found')
        }

    } catch (err) {
        errors.push({place: "checkPassword function", error: err.message});
    }
}


async function userInDb (email) {
    const userProfileDbResponse = await pool.query(`SELECT * FROM users WHERE user_email=$1`, [email]);
    const isThereOnlyOne = userProfileDbResponse.rowCount === 1;
    const data = userProfileDbResponse.rows[0];

    return {isThereOnlyOne: isThereOnlyOne, data: data}
}


app.post ("/signup", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        let usersWithThisNameOrEmail = await pool.query("SELECT * FROM users WHERE user_email = $1", [email]);
        usersWithThisNameOrEmail = usersWithThisNameOrEmail.rowCount;

        if (usersWithThisNameOrEmail === 0) {

            let date = new Date(Date.now());

            const saltRounds = 10;
            await bcrypt.hash(password, saltRounds, function (err, hashedPassword) {
                pool.query ("INSERT INTO users (user_name, user_email, user_password, registration_date) VALUES ($1, $2, $3, $4)",
                    [name, email, hashedPassword, date]);
            });

            const token = await generateEmailVerificationToken({email});
            await sendVerificationEmail(email, token);

            res.send('User successfully added');

        } else {

            errors.push({place: "post /signup", error: `User with email ${email} already exists`});
            res.sendStatus(403);
        }

    } catch (err) {
        errors.push({place: "post /signup", error: err.message});
    }
});



app.get ("/email/verify", authenticateEmailToken, async (req, res) => {


    try {

        const email = req.email;

        const user = await userInDb(email);

        if (user.isThereOnlyOne) {
            await pool.query("UPDATE users SET user_active=$1 WHERE user_email=$2", [true, email]);
        }

        res.sendStatus(200);

    } catch (err) {

        res.send("Проверка email не удалась");
        errors.push({place: "post /email/verify", error: err.message});

    }

});




app.post ("/login", async (req, res) => {

    const { email, password } = req.body;

    try {

        const user = await userInDb(email);


        if (user.isThereOnlyOne) {

            const hashedPassword = user.data.user_password;
            const isPasswordCorrect = await bcrypt.compare(password, hashedPassword);


            if (isPasswordCorrect) {

               const accessToken = await generateAccessToken({email});
               const refreshToken = await jwt.sign(email, process.env.REFRESH_TOKEN_SECRET);

                console.log(accessToken, refreshToken);

               const dbValidTokens = await pool.query("SELECT * FROM valid_refresh_tokens WHERE user_email = $1", [email]);
               const hasUserGotValidToken = dbValidTokens.rowCount > 0;

               if (!hasUserGotValidToken) {

                   let date = new Date(Date.now());
                   await pool.query("INSERT INTO valid_refresh_tokens (token, token_added, user_email) VALUES ($1, $2, $3)",
                       [refreshToken, date, email]);
               }


               res.cookie('telecom-dashboard-user-name', email, USER_EMAIL_COOKIE_OPTIONS);
               res.cookie('refreshToken', refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);
               await res.json({ accessToken: accessToken, refreshToken: refreshToken });

            } else {

                errors.push({place: "post /login", error: "Password is incorrect"});
                res.sendStatus(401);

            }

        } else {

            errors.push({place: "post /login", error: "User database has been corrupted"});
            res.sendStatus(500);
        }

    } catch (err) {

        errors.push({place: "post /login", error: err.message});

    }

});




// refresh access token
app.get("/token", (req, res) => {

    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) return res.sendStatus(401);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, email) => {

        if (err) return res.send(err.message);

        const validRefreshTokensInDb = await pool.query("SELECT * FROM valid_refresh_tokens WHERE user_email = $1", [email]);

        if (validRefreshTokensInDb.rowCount > 0) {

            const validRefreshTokenInDb = validRefreshTokensInDb.rows[0].token;
            if (validRefreshTokenInDb !== refreshToken) return res.sendStatus(401);

        }

        res.cookie('telecom-dashboard-user-email', email, USER_EMAIL_COOKIE_OPTIONS);
        const accessToken = generateAccessToken({email: email});
        return res.json({accessToken: accessToken, email: email});

    });

});


app.delete("/logout", async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    const validRefreshTokensInDb = await pool.query("SELECT * FROM valid_refresh_tokens WHERE token = $1",
        [refreshToken]);

    if (validRefreshTokensInDb.rowCount > 0) {
        await pool.query("DELETE FROM valid_refresh_tokens WHERE token = $1", [refreshToken]);
    }

    res.sendStatus(204);
});




app.post("/dashboard", authenticateToken, async (req, res) => {
    //const dbResponse = await pool.query("SELECT * FROM notes WHERE note_owner_name = $1", [req.user.name]);


    const {section, page} = req.body;
    //console.log(section, page);

    const email = req.user.email;
    const user = await userInDb(email);


    if (user.data.user_active) {

        // the awkward "tabs" is used instead of "pages" because the "pages" is a keyword
        if ( section !== "profile") {

            const responseWithContent = {
                "content": json_dummy_user[section].tabs[page - 1],
                "section": section,
                "tabsCount": json_dummy_user[section].tabs_count,
                "tab": page
            };
            await res.json(responseWithContent);

        } else {

            const data = user.data;

            const content = {
                "user_name": data.user_name,
                "user_email": data.user_email,
                "company_name": data.company_name,
                "account_balance": data.account_balance,
                "city_name": data.city_name,
                "registration_date": data.registration_date
            };

            const responseWithContent = {
                "content": content,
                "section": "profile"
            };

            await res.json(responseWithContent);
        }

    } else {

        const content = {
            user_status: "неактивен",
            message: "Воспользуйтесь ссылкой в сообщении, " +
                "которое было отправлено на указанный при регистрации email," +
                "чтобы активировать учетную запись"
        };

        const responseWithContent = {
            "content": content,
            "section": "profile"
        };

        await res.json(responseWithContent);

    }

});


app.post("/dashboard/edit-user-profile", authenticateToken, async (req, res) => {

    const {fieldsToEdit, email} = req.body;

    if (email && fieldsToEdit.length > 0) {

        try {
            let query = ["UPDATE users SET "];
            const queryValues = [];

            for (let i = 0; i < fieldsToEdit.length; i++) {
                query.push(`${fieldsToEdit[i].field}=$${i+1} `);
                queryValues.push(fieldsToEdit[i].value);
            }

            query.push(`WHERE user_email=$${fieldsToEdit.length + 1}`);
            query = query.join("");
            queryValues.push(email);

            await pool.query(query, queryValues);

            await res.send("profile edit success");

        } catch (err) {
            console.error(err.message);
        }

    }




});



// TODO get rid of callbacks and add feedback
app.post("/auth/change_password", async (req, res) => {
    const { user, oldPassword, newPassword } = req.body;

    try {
        const checkPasswordResponse = await checkPassword(user, oldPassword);
        if (checkPasswordResponse === 'password is correct') {
            const saltRounds = 10;
            let changePasswordResponse;
            await bcrypt.hash(newPassword, saltRounds, (err, hashedPassword) => {
                changePasswordResponse =  pool.query ("UPDATE users SET user_password=$1 WHERE user_name=$2",
                    [hashedPassword, user]);
            });
        }
        res.sendStatus(200);

    } catch (err) {
        if (err.message === 'password is incorrect') return res.send('password is incorrect');
        if (err.message === 'user not found') return res.send('user not found');
        console.error(err.message);
    }
});





app.get('/errors', (req, res) => {
    res.send(errors && errors);
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`The server is running on port ${PORT}`);
});
