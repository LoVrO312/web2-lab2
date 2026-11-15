require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');


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
        <h1>Zadatak 1. - SQL umetanje</h1>
        <form method="POST" action="/login">
            <input name="username" placeholder="korisničko ime"><br>
            <input type="password" name="password" placeholder="lozinka"><br>
            <label><input type="checkbox" name="safeMode"> Sigurni način</label><br>
            <button>Prijava</button>
        </form>
        <p>Napadi (korisničko ime ostaviti prazno, upisati u polje <b>lozinka</b>, sigurni način isključen):</p>
        <table cellpadding="8">
            <tr><td>' OR '1'='1</td><td>-> prijava bez ispravnog korisničkog imena i lozinke (tautologija)</td></tr>
            <tr><td>'; UPDATE users SET role='admin' WHERE username='ivan'--</td><td>-> ivan dobije ulogu admin (aplikacija javi grešku; prijavom kao ivan potvrdite da je umetanje uspjelo)</td></tr>
            <tr><td>' UNION SELECT 1, version(), 'x', 'y', current_user --</td><td>-> verzija i korisnik baze</td></tr>
        </table>

        <p><b>Testni korisnici:</b></p>
        <ul>
            <li>admin / tajna123 (uloga: admin)</li>
            <li>ivan / ivan123 (uloga: user)</li>
        </ul>
        <a href="/auth">2. Zadatak</a>
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

app.get('/auth', (req, res) => {
    res.send(`
        <h1>Zadatak 2. - Loša autentifikacija</h1>
        <form method="POST" action="/auth/login">
            <input name="username" placeholder="korisničko ime" value="admin"><br>
            <input type="password" name="password" placeholder="lozinka"><br>
            <label><input type="checkbox" name="safeMode"> Sigurni način</label><br>
            <button>Prijava</button>
        </form>

        <hr>
        <p>Brute-force napad: skripta u pregledniku isprobava lozinke na /auth/login za korisnika "admin" dok ne pogodi. Siguran način rada je rate limitan na 3 pokušaja, nakon toga zaključava prijave na taj račun na 30 sekundi</p>
        <label><input type="checkbox" id="bruteSafe"> Sigurni način</label><br>
        <button onclick="brute()">Pokreni brute-force</button>
        <pre id="bruteOut"></pre>
        <a href="/">1. Zadatak</a>

        <script>
            async function brute() {
                const safe = document.getElementById('bruteSafe').checked;
                const passwords = ['1', '12', '123', '1234', 'tajna123', 'ivan123'];
                const out = document.getElementById('bruteOut');
                out.textContent = '';
                for (const pw of passwords) {
                    out.textContent += 'Isprobavam lozinku: ' + pw + '\\n';

                    const response = await fetch('/auth/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: new URLSearchParams({
                            username: 'admin',
                            password: pw,
                            safeMode: safe ? 'on' : ''
                        })
                    });

                    if (response.ok) {
                        out.textContent += 'Pogodak! Lozinka je "' + pw + '"\\n';
                        break;
                    }

                    if (response.status === 429) {
                        out.textContent += 'Rate limit dosegnut - napad zaustavljen';
                        break;
                    }
                }
            }
        </script>
    `);
});

const attempts = {}; // brojač pokušaja prijave po korisničkom imenu
const MAX_TRIES = 3;
const LOCK_MS = 30 * 1000;  // zaključavamo prijave na račun na 30 sekundi

app.post('/auth/login', async (req, res) => {
    const { username, password, safeMode } = req.body;
    const result = await db.query('SELECT * FROM users WHERE username=$1', [username]);
    const user = result.rows[0];
    const a = attempts[username] || { count: 0, lockUntil: 0 };

    // lockout: samo u sigurnom načinu, i samo dok traje vremenski prozor
    if (safeMode && Date.now() < a.lockUntil) {
        return res.status(429).send(`<h2>Previše pokušaja - račun zaključan!</h2><a href="/auth">natrag</a>`);
    }

    let ok = false;
    if (user) {
        ok = safeMode
            ? bcrypt.compareSync(password, user.password_hash) // sigurno: usporedba s hashom
            : password === user.password; // ranjivo: plaintext usporedba
    }

    if (!ok) {
        if (safeMode) {
            a.count++;
            if (a.count >= MAX_TRIES) { a.lockUntil = Date.now() + LOCK_MS; a.count = 0; }
            attempts[username] = a;
        }
        const message = safeMode
            ? 'Pogrešni podaci za prijavu.' // generička poruka ne otkriva informacije
            : (user ? 'Pogrešna lozinka!' : 'Korisnik ne postoji!');// ranjivo: napadač može utvrditi koji računi postoje
        return res.status(401).send(`<h2>${message}</h2><a href="/auth">natrag</a>`);
    }

    delete attempts[username]; // uspješna prijava resetira brojač
    const sessionId = safeMode
        ? crypto.randomBytes(16).toString('hex') // sigurno: nasumičan session ID
        : 'session-' + username;               // ranjivo: predvidljiv session iD
    res.cookie('session', sessionId, {
        httpOnly: !!safeMode,   // false -> ranjivo: JS može čitati cookie (document.cookie)
        secure: !!safeMode,     // true -> kolačić se šalje samo preko HTTPS
        sameSite: safeMode ? 'strict' : 'lax'
    });
    res.send(`
        <h2>Prijavljen kao ${user.username} (uloga: ${user.role})</h2>
        <p>Session kolačić postavljen. HttpOnly: ${!!safeMode}</p>
        <button onclick="alert('document.cookie = ' + document.cookie)">Prikaži kolačić (napad)</button>
        <p><a href="/auth">natrag</a></p>
    `);
});

async function start() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
    `);

    const admin_password = "tajna123";
    const ivan_password = "ivan123";
    const hash_admin = bcrypt.hashSync(admin_password);
    const hash_ivan = bcrypt.hashSync(ivan_password);
    
    await db.query(
        `INSERT INTO users (username, password, password_hash, role) VALUES
            ($1, $2, $3, 'admin'),
            ($4, $5, $6, 'user')
         ON CONFLICT (username) DO NOTHING;`,
        [
            'admin', admin_password, hash_admin,
            'ivan',  ivan_password,  hash_ivan
        ]
    );

      app.listen(PORT, () => console.log(`Aplikacija radi na ${BASE_URL}`));
}

start();
