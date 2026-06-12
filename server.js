const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const app = express();
const PORT = process.env.PORT || 3000;

// Render läuft hinter einem Proxy, das müssen wir Express sagen, 
// damit wir die ECHTEN IP-Adressen der Angreifer bekommen.
app.set('trust proxy', 1);

let gespeicherterText = "Kein Text hinterlegt.";
const ADMIN_PASSWORT = process.env.ADMIN_PASSWORD || "Achtung_Du_Musst_Ein_Passwort_Bei_Render_Eintragen_123456789";

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: 'ein-zufälliger-geheimer-schlüssel-für-cookies',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 } // 30 Minuten gültig
}));

// --- COOLDOWN SYSTEM (Rate Limiting) ---
// Maximal 5 Login-Versuche pro IP alle 15 Minuten
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 Minuten
    max: 5, // Maximal 5 Versuche
    message: '<h1>Zu viele Fehlversuche!</h1><p>Diese IP wurde für 15 Minuten gesperrt. Bitte warte, bevor du es erneut versuchst.</p>',
    standardHeaders: true,
    legacyHeaders: false,
});

function entschärfeText(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// 1. Startseite
app.get('/', (req, res) => {
    res.send(`<h1>Willkommen!</h1><p>Aktueller Text: <b>${entschärfeText(gespeicherterText)}</b></p>`);
});

// 2. Login-Maske
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

// Hier greift jetzt die IP-Sperre (loginLimiter) bei jedem Login-Versuch!
app.post('/admin/login', loginLimiter, (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORT) {
        req.session.eingeloggt = true;
        res.redirect('/admin/dashboard');
    } else {
        res.send('<h1>Falsches Passwort!</h1><a href="/admin">Nochmal versuchen</a>');
    }
});

// 3. Das Dashboard
app.get('/admin/dashboard', (req, res) => {
    if (!req.session.eingeloggt) {
        return res.redirect('/admin'); // Schickt unbefugte User elegant zurück zum Login
    }

    res.send(`
        <h1>Admin Dashboard</h1>
        <p>Aktueller Text auf dem Server: <b>${entschärfeText(gespeicherterText)}</b></p>
        <form action="/admin/update-text" method="POST">
            <input type="text" name="neuerText" placeholder="Neue Textzeile" required style="width: 300px;"><br><br>
            <button type="submit">Text aktualisieren</button>
        </form>
        <br>
        <a href="/admin/logout">Ausloggen</a>
    `);
});

app.post('/admin/update-text', (req, res) => {
    if (!req.session.eingeloggt) {
        return res.status(403).send('Zugriff verweigert!');
    }
    gespeicherterText = req.body.neuerText;
    res.redirect('/admin/dashboard');
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

// 4. HEADLESS Aufruf mit automatischer Selbstzerstörung!
app.get('/headless', (req, res) => {
    res.set('Content-Type', 'text/plain; charset=utf-8');
    
    // 1. Wir merken uns den aktuellen Text
    const textZuSenden = gespeicherterText;
    
    // 2. Wir löschen den Text SOFORT auf dem Server
    gespeicherterText = "Kein Text hinterlegt (wurde bereits abgegriffen).";
    
    // 3. Wir senden den gemerkten Text an den Aufrufer
    res.send(textZuSenden);
});

app.listen(PORT, () => {
    console.log(`Hochsicherer Server läuft auf Port ${PORT}`);
});
