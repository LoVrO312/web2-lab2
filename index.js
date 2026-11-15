require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : false
});

const app = express();
app.set('trust proxy', 1); // render je iza https proxyja
app.use(express.urlencoded({ extended: true }));



app.get('/', (req, res) => {
    res.send(`
        <h1>SQL umetanje</h1>
        <form method="POST" action="/login">
            <input name="username" placeholder="korisničko ime"><br>
            <input name="password" placeholder="lozinka"><br>
            <label><input type="checkbox" name="safeMode"> Sigurni način(parametrizirano)</label><br>
            <button>Prijava</button>
        </form>
        <p>Napad: polje korisničko ime ostaviti prazno, a u polje lozinka upisati <b>' OR '1'='1</b></p>
    `);
});

app.post('/login', async (req, res) => {
    const {username, password, safeMode } = req.body;
    let sql, result;

    try {
        if (safeMode) {
            sql = "SELECT * FROM users WHERE username=$1 AND password=$2";
            result = await db.query(sql, [username, password]);
        } else {
            sql = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
            result = await db.query(sql);
        }
    } catch (e) {
        return res.send(`
            <h2>Izvršeni SQL</h2>
            ${sql} <br>
            GREŠKA: ${e.message} <br>
            <a href="/">natrag</a>`);
    }

    const user = result.rows[0];
    res.send(`
        <h2>${user ? 'Prijavljen kao: ' + user.username + '<br> uloga: ' + user.role : 'Prijava neuspješna'}</h2>
        <h3>Izvršeni SQL:</h3>
        ${sql}<br>
        <a href="/">natrag</a>
    `);
});

async function start() {
    await db.query('DROP TABLE IF EXISTS users'); //!
    await db.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
    `);
    await db.query(`
        INSERT INTO users (username, password, role) VALUES
            ('admin', 'tajna123', 'admin'),
            ('ivan',  'ivan123','user')
        ON CONFLICT (username) DO NOTHING;
    `);

      app.listen(PORT, () => console.log(`Aplikacija radi na ${BASE_URL}`));
}

start();
