const Pool = require("pg").Pool;


// make sure to set these environment variables to access the DB
const pool = new Pool ({
    user: process.env.PG_DB_USER,
    password: process.env.PG_DB_PASSWORD,
    host: process.env.PG_DB_HOST,
    port: process.env.PG_DB_PORT,
    database: process.env.PG_DB_NAME
});

module.exports = pool;