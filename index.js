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
const json_dummy = require("./db/json");
const json_dummy_user = require("./db/user");



app.use(router);

const CORS_OPTIONS = {
    origin: process.env.FRONTEND_HOST,
    credentials: true,
    preflightContinue: true
};

const USER_NAME_COOKIE_OPTIONS = { expires: utils.cookieExpiresIn(14), httpOnly: false, sameSite: "none", secure: true};

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


app.post ("/signup", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        let usersWithThisNameOrEmail = await pool.query("SELECT * FROM users WHERE user_name = $1" +
            "OR user_email = $2", [name, email]);
        usersWithThisNameOrEmail = usersWithThisNameOrEmail.rowCount;

        if (usersWithThisNameOrEmail === 0) {
            const saltRounds = 10;
            await bcrypt.hash(password, saltRounds, function (err, hashedPassword) {
                pool.query ("INSERT INTO users (user_name, user_email, user_password) VALUES ($1, $2, $3)",
                    [name, email, hashedPassword]);
            });
            res.send('User successfully added');

        } else {
            errors.push({place: "post /signup", error: `User with name ${name} or email ${email} already exists`});
            res.sendStatus(403);
        }

    } catch (err) {
        errors.push({place: "post /signup", error: err.message});
    }
});

async function checkPassword (name, password) {
    try {
        const dbResponse = await pool.query("SELECT * FROM users WHERE user_name = $1", [name]);
        const numberOfUsers = dbResponse.rowCount;

        if (numberOfUsers === 1) {
            const hashedPassword = dbResponse.rows[0].user_password;
            const isPasswordCorrect = await bcrypt.compare(password, hashedPassword);

            // check the password
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



app.post ("/login", async (req, res) => {

    const { name, password } = req.body;

    try {
        const dbResponse = await pool.query("SELECT * FROM users WHERE user_name = $1", [name]);
        const numberOfUsers = dbResponse.rowCount;

        if (numberOfUsers === 1) {

            const hashedPassword = dbResponse.rows[0].user_password;
            const isPasswordCorrect = await bcrypt.compare(password, hashedPassword);

            // check the password
            if (isPasswordCorrect) {
               const accessToken = await generateAccessToken({name});
               const refreshToken = await jwt.sign(name, process.env.REFRESH_TOKEN_SECRET);

               const dbValidTokens = await pool.query("SELECT * FROM valid_refresh_tokens WHERE user_name = $1", [name]);
               const hasUserGotValidToken = dbValidTokens.rowCount > 0;

               if (!hasUserGotValidToken) {
                   let date = new Date(Date.now());
                   await pool.query("INSERT INTO valid_refresh_tokens (token, token_added, user_name) VALUES ($1, $2, $3)", [refreshToken, date, name]);
               }



               res.cookie('telecom-dashboard-user-name', name, USER_NAME_COOKIE_OPTIONS);
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

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, name) => {
        if (err) return res.send(err.message);

        const validRefreshTokensInDb = await pool.query("SELECT * FROM valid_refresh_tokens WHERE user_name = $1", [name]);

        if (validRefreshTokensInDb.rowCount > 0) {
            const validRefreshTokenInDb = validRefreshTokensInDb.rows[0].token;
            if (validRefreshTokenInDb !== refreshToken) return res.sendStatus(401);
        }

        res.cookie('unnotateUserName', name, USER_NAME_COOKIE_OPTIONS);
        const accessToken = generateAccessToken({name: name});
        return res.json({accessToken: accessToken, name: name});
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


app.get("/profile", authenticateToken, async (req, res) => {
    //const dbResponse = await pool.query("SELECT * FROM notes WHERE note_owner_name = $1", [req.user.name]);
    await res.json(json_dummy_user);
});


app.get("/dashboard", authenticateToken, async (req, res) => {
    //const dbResponse = await pool.query("SELECT * FROM notes WHERE note_owner_name = $1", [req.user.name]);
    await res.json(json_dummy.objects);
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


function generateAccessToken(user) {
    console.log(user);
    const TOKEN_EXPIRATION_TIME = '15m';
    return  jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: TOKEN_EXPIRATION_TIME });
}

app.get('/errors', (req, res) => {
    res.send(errors && errors);
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`The server is running on port ${PORT}`);
});
