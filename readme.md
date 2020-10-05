# Telecom Dashboard Server

Telecom Dashboard server is a backend for Telecom Dashboard, a demo client area of a telecommunications company. 
The backend is built using:
 * Node.js
 * Postgres
 * JWT
 * Express

## Installation

git clone https://github.com/ischekoldin/telecom-dashboard-server.git

## Usage

```
// to start on localhost, the default port is 5000
npm devstart
// to start in production
npm start
```

## Important

 * Telecom Dashboard saves session using cross site cookies. Modern browsers require those to be sent only through https://.
Therefore, your frontend has to be accessed through https. However, if you host both frontend and backend on the same domain,
you can set `sameSite` in `src/DashBoard/DashBoard.js` in `REFRESH_TOKEN_COOKIE_OPTIONS` to `"lax"` and `secure` option to `"false"`
 * Make sure to set database options in environment variables, for example:
 ```  
      PG_DB_USER = "jack"
      PG_DB_PASSWORD = "12345678"
      PG_DB_HOST = "db.amazonaws.com"
      PG_DB_PORT = "5432"
      PG_DB_NAME = "unnotate"
```
 * Set frontend host in environment variables  (ex: `FRONTEND_HOST = "https://hostname.com"`). If this variable isn't set,
`localhost:5000` is used as a frontend host. By default the backend only accepts connections from one address 
but you can can set an array or regex. It can be done in `CORS_OPTIONS > origin` that can be found in `src/index.js`.


## License
[ISC](http://opensource.org/licenses/ISC)

