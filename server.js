const express = require('express');
const session = require('express-session');
const app = express();
const PORT = process.env.PORT || 3000;

let gespeicherterText = "Das ist die Standard-Zeile.";
const ADMIN_PASSWORT = process.env.ADMIN_PASSWORD || "Achtung_Du_Musst_Ein_Passwort_Bei_Render_Eintragen_123456789";

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Das hier ist das "Gedächtnis" des Servers für Logins
app.use(session({
    secret: 'ein-zufälliger-geheimer-schlüssel-für-cookies',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 } // Login ist 30 Minuten lang gültig
}));

function entschärfeText(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// 1. Startseite
app.get('/', (req, res) => {
    res.send(`<h1>Willkommen!</h1><p>Text: <b>${entschärfeText(gespeicherterText)}</b></p>`);
});

// 2. Login-Maske (Hier sieht man NUR das Passwortfeld!)
app.get('/admin', (req, res) => {
    if (req.session.eingeloggt) {
        return res.redirect('/admin/dashboard');
    }
    res.send(`
        <h1>Admin Login</h1>
        <form action="/admin/login" method="POST">
            <input type="password" name="password" placeholder="Passwort" required><br><br>
            <button type="submit">Einloggen</button>
        </form>
    `);
});

// Hier wird das Passwort geprüft
app.post('/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORT) {
        req.session.eingeloggt = true; // Der Server merkt sich: Dieser User darf rein!
        res.redirect('/admin/dashboard');
    } else {
        res.send('<h1>Falsches Passwort!</h1><a href="/admin">Nochmal versuchen</a>');
    }
});

// 3. Das echte Dashboard (Gesperrt für alle ohne Login!)
app.get('/admin/dashboard', (req, res) => {
    // Sicherheits-Check: Ist der User eingeloggt?
    if (!req.session.eingeloggt) {
        return res.status(403).send('<h1>Zugriff verweigert!</h1><p>Du musst dich zuerst <a href="/admin">einloggen</a>.</p>');
    }

    // Erst HIER wird das Textfeld angezeigt!
    res.send(`
        <h1>Admin Dashboard</h1>
        <p>Aktueller Text: <b>${entschärfeText(gespeicherterText)}</b></p>
        <form action="/admin/update-text" method="POST">
            <input type="text" name="neuerText" placeholder="Neue Textzeile" required style="width: 300px;"><br><br>
            <button type="submit">Text aktualisieren</button>
        </form>
        <br>
        <a href="/admin/logout">Ausloggen</a>
    `);
});

// Hier wird der Text geändert (Ebenfalls streng gesperrt)
app.post('/admin/update-text', (req, res) => {
    if (!req.session.eingeloggt) {
        return res.status(403).send('Zugriff verweigert!');
    }
    gespeicherterText = req.body.neuerText;
    res.redirect('/admin/dashboard');
});

// Ausloggen
app.get('/admin/logout', (req, res) => {
    req.session.destroy();
    res.send('<h1>Ausgeloggt!</h1><a href="/admin">Zum Login</a>');
});

// 4. Headless-Aufruf (Gibt NUR den Text zurück)
app.get('/headless', (req, res) => {
    res.set('Content-Type', 'text/plain; charset=utf-8');
    res.send(gespeicherterText);
});

app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
});
