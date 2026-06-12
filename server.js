const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// WICHTIG: Das hier verbietet dem Browser das Caching. 
// Es fixt den Fehler, dass man erst F5 drücken muss!
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

let gespeicherterTextBase64 = Buffer.from("Kein Text hinterlegt.").toString('base64');
const ADMIN_PASSWORT = process.env.ADMIN_PASSWORD || "Achtung_Du_Musst_Ein_Passwort_Bei_Render_Eintragen_123456789";

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: 'ein-zufälliger-geheimer-schlüssel-für-cookies',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: '<h1>Zu viele Fehlversuche!</h1><p>Bitte warte 15 Minuten.</p>',
    standardHeaders: true,
    legacyHeaders: false,
});

// 1. Startseite: Schickt ein komplett leeres Dokument (wirkt wie about:blank)
app.get('/', (req, res) => {
    res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>');
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
        return res.redirect('/admin');
    }

    // Wir decodieren den Text kurz für dich im Dashboard, damit du siehst, was drin steht
    const normalerText = Buffer.from(gespeicherterTextBase64, 'base64').toString('utf-8');

    res.send(`
        <h1>Admin Dashboard</h1>
        <p>Aktueller Text (Klartext): <b>${normalerText}</b></p>
        <p>Aktueller Text (Base64): <code>${gespeicherterTextBase64}</code></p>
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
    // Hier wandeln wir deinen Text direkt in Base64 um, bevor er gespeichert wird!
    gespeicherterTextBase64 = Buffer.from(req.body.neuerText).toString('base64');
    res.redirect('/admin/dashboard');
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

// 4. Intelligenter HEADLESS Aufruf auf der Route /headless
app.get('/headless', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    
    // Prüfen, ob der Aufruf von einem normalen Browser kommt (Firefox, Chrome, Safari, Edge, Brave etc.)
    const istBrowser = /Mozilla|Chrome|Safari|Firefox|Edge|Brave/i.test(userAgent);

    if (istBrowser) {
        // Wenn es ein normaler Browser ist, tun wir so, als gäbe es hier nichts (Leere Seite)
        return res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>');
    }

    // Wenn es HEADLESS ist (Terminal, curl, wget, python-skript etc.):
    res.set('Content-Type', 'text/plain; charset=utf-8');
    
    const textZuSenden = gespeicherterTextBase64;
    
    // Text nach dem Abgreifen sofort zerstören
    gespeicherterTextBase64 = Buffer.from("Kein Text hinterlegt.").toString('base64');
    
    res.send(textZuSenden);
});

app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
});
