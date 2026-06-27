import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import helmet from 'helmet';
import cors from 'cors';
import multer from 'multer';
import sqlite3 from 'sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import session from 'express-session';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);

// Sécurité basique tout en permettant le chargement des scripts CDN React
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const PORT = process.env.PORT || 3000;
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
    cors: { origin: true, credentials: true }
});

// ============ MIDDLEWARES ============
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '5mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/audios', express.static(path.join(__dirname, 'audios')));
app.use('/stories', express.static(path.join(__dirname, 'stories')));

const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || 'snapquest_secret_2026_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware); // Partage de session avec Socket.io

// ============ WEBSOCKETS (TEMPS RÉEL) ============
let onlineUsers = new Set();
io.on('connection', (socket) => {
    const userId = socket.request.session?.userId;
    if (userId) {
        onlineUsers.add(userId);
        io.emit('online_count', onlineUsers.size);

        socket.on('disconnect', () => {
            onlineUsers.delete(userId);
            io.emit('online_count', onlineUsers.size);
        });
    }
});

// ============ DOSSIERS ============
const uploadsDir = path.join(__dirname, 'uploads');
const audiosDir = path.join(__dirname, 'audios');
const storiesDir = path.join(__dirname, 'stories');

[uploadsDir, audiosDir, storiesDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`📁 Dossier créé: ${dir}`);
    }
});

// ============ BASE DE DONNÉES ============
const db = new sqlite3.Database(path.join(__dirname, 'snapquest.db'));

db.run('PRAGMA journal_mode=WAL');
db.run('PRAGMA synchronous=NORMAL');
db.run('PRAGMA cache_size=10000');
db.run('PRAGMA temp_store=MEMORY');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, full_name TEXT, profile_pic TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY AUTOINCREMENT, image_url TEXT NOT NULL, caption TEXT DEFAULT '', user_id INTEGER NOT NULL, user_name TEXT, created_date DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    db.run(`CREATE TABLE IF NOT EXISTS likes (user_id INTEGER NOT NULL, photo_id INTEGER NOT NULL, PRIMARY KEY (user_id, photo_id), FOREIGN KEY (photo_id) REFERENCES photos(id) ON DELETE CASCADE)`);
    db.run(`CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, photo_id INTEGER NOT NULL, user_id INTEGER NOT NULL, user_name TEXT, text TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (photo_id) REFERENCES photos(id) ON DELETE CASCADE)`);
    db.run(`CREATE TABLE IF NOT EXISTS global_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, user_name TEXT, text TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS audios (id INTEGER PRIMARY KEY AUTOINCREMENT, file_url TEXT NOT NULL, title TEXT DEFAULT 'Sans titre', artist TEXT DEFAULT 'Artiste inconnu', user_id INTEGER NOT NULL, user_name TEXT, created_date DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`);
    db.run(`CREATE TABLE IF NOT EXISTS stories (id INTEGER PRIMARY KEY AUTOINCREMENT, image_url TEXT NOT NULL, caption TEXT DEFAULT '', user_id INTEGER NOT NULL, user_name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME DEFAULT (datetime('now', '+24 hours')), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)`);

    db.run(`CREATE INDEX IF NOT EXISTS idx_photos_created ON photos(created_date DESC)`);
    db.run(`UPDATE photos SET user_name = (SELECT full_name FROM users WHERE users.id = photos.user_id) WHERE user_name IS NULL`);
    console.log('✅ Base de données prête');
});

// ============ MULTER CONFIG ============
const MAX_AUDIO_SIZE = 50 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'];
const ALLOWED_AUDIO_TYPES = ['audio/mpeg', 'audio/mp3', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/m4a', 'audio/x-m4a', 'audio/aac'];

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dest = file.fieldname === 'audio' ? audiosDir : file.fieldname === 'story' ? storiesDir : uploadsDir;
        cb(null, dest);
    },
    filename: (req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname)}`)
});

const fileFilter = (req, file, cb) => {
    if (file.fieldname === 'audio') ALLOWED_AUDIO_TYPES.includes(file.mimetype) ? cb(null, true) : cb(new Error(`Type audio non supporté`), false);
    else ALLOWED_IMAGE_TYPES.includes(file.mimetype) ? cb(null, true) : cb(new Error(`Type image non supporté`), false);
};

const upload = multer({ storage, fileFilter, limits: { fileSize: MAX_AUDIO_SIZE } });

const rateLimits = new Map();
const rateLimit = (max, windowMs) => (req, res, next) => {
    const key = req.session?.userId || req.ip;
    const now = Date.now();
    const window = rateLimits.get(key) || { count: 0, reset: now + windowMs };
    if (now > window.reset) { window.count = 0; window.reset = now + windowMs; }
    window.count++;
    rateLimits.set(key, window);
    if (window.count > max) return res.status(429).json({ error: 'Trop de requêtes.' });
    next();
};

const isAuthenticated = (req, res, next) => req.session?.userId ? next() : res.status(401).json({ error: 'Non authentifié' });
const sanitize = (str, maxLen = 500) => (typeof str === 'string' ? str.trim().slice(0, maxLen).replace(/[&<>]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[m])) : '');

// ============ ROUTES ============
app.post('/api/auth/register', rateLimit(5, 60000), async (req, res) => {
    const username = sanitize(req.body.username, 30);
    const password = sanitize(req.body.password, 128);
    const full_name = sanitize(req.body.full_name || username, 60);

    try {
        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, full_name) VALUES (?, ?, ?)', [username, hash, full_name], function(err) {
            if (err) return res.status(400).json({ error: 'Ce nom d\'utilisateur est déjà pris' });
            req.session.userId = this.lastID;
            res.json({ user: { id: this.lastID, username, full_name, profile_pic: '' } });
        });
    } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/auth/login', rateLimit(10, 60000), (req, res) => {
    db.get('SELECT * FROM users WHERE username = ?', [sanitize(req.body.username, 30)], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(sanitize(req.body.password, 128), user.password))) return res.status(401).json({ error: 'Identifiants invalides' });
        req.session.userId = user.id;
        res.json({ user: { id: user.id, username: user.username, full_name: user.full_name, profile_pic: user.profile_pic } });
    });
});

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ success: true })));

app.get('/api/me', (req, res) => {
    if (!req.session?.userId) return res.json(null);
    db.get('SELECT id, username, full_name, profile_pic FROM users WHERE id = ?', [req.session.userId], (err, user) => res.json(err || !user ? null : user));
});

// PHOTOS (Avec Pagination)
app.get('/api/photos', isAuthenticated, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const queryPhotos = `
        SELECT p.id, p.image_url, p.caption, p.user_id, p.user_name, p.created_date,
               u.profile_pic AS user_avatar, u.username AS current_username, u.full_name AS current_fullname,
               COUNT(DISTINCT l.user_id) AS likesCount, MAX(CASE WHEN l.user_id = ? THEN 1 ELSE 0 END) AS isLikedByMe
        FROM photos p LEFT JOIN users u ON p.user_id = u.id LEFT JOIN likes l ON l.photo_id = p.id
        GROUP BY p.id ORDER BY p.created_date DESC LIMIT ? OFFSET ?`;

    db.all(queryPhotos, [req.session.userId, limit, offset], (err, photos) => {
        if (err || !photos || photos.length === 0) return res.json([]);
        const photoIds = photos.map(p => p.id);
        const queryComments = `
            SELECT c.id, c.photo_id, c.user_id, c.text, c.created_at, u.profile_pic AS user_avatar, u.full_name AS current_fullname
            FROM comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.photo_id IN (${photoIds.map(()=>'?').join(',')}) ORDER BY c.created_at ASC`;

        db.all(queryComments, photoIds, (err, comments) => {
            const commentsMap = {};
            (comments || []).forEach(c => { if (!commentsMap[c.photo_id]) commentsMap[c.photo_id] = []; commentsMap[c.photo_id].push(c); });
            res.json(photos.map(p => ({ ...p, isLikedByMe: Boolean(p.isLikedByMe), comments: commentsMap[p.id] || [] })));
        });
    });
});

app.post('/api/photos', isAuthenticated, upload.single('file'), (req, res) => {
    db.get('SELECT full_name, username, profile_pic FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        db.run('INSERT INTO photos (image_url, caption, user_id, user_name) VALUES (?, ?, ?, ?)',
            [`/uploads/${req.file.filename}`, sanitize(req.body.caption, 500), req.session.userId, user.full_name], function(err) {
            
            // Re-fetch complete photo data to broadcast via WebSocket
            db.get(`SELECT p.*, u.profile_pic AS user_avatar, u.username AS current_username, u.full_name AS current_fullname 
                    FROM photos p LEFT JOIN users u ON p.user_id = u.id WHERE p.id = ?`, [this.lastID], (err, newPhoto) => {
                newPhoto.likesCount = 0; newPhoto.isLikedByMe = false; newPhoto.comments = [];
                io.emit('new_photo', newPhoto);
                res.json(newPhoto);
            });
        });
    });
});

app.post('/api/photos/:id/like', isAuthenticated, (req, res) => {
    db.get('SELECT 1 FROM likes WHERE user_id = ? AND photo_id = ?', [req.session.userId, req.params.id], (err, row) => {
        const query = row ? 'DELETE FROM likes WHERE user_id = ? AND photo_id = ?' : 'INSERT INTO likes (user_id, photo_id) VALUES (?, ?)';
        db.run(query, [req.session.userId, req.params.id], () => {
            io.emit('update_like', { photoId: parseInt(req.params.id), delta: row ? -1 : 1 });
            res.json({ liked: !row });
        });
    });
});

app.post('/api/photos/:id/comments', isAuthenticated, (req, res) => {
    const text = sanitize(req.body.text, 500);
    db.get('SELECT full_name, profile_pic FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        db.run('INSERT INTO comments (photo_id, user_id, user_name, text) VALUES (?, ?, ?, ?)', [req.params.id, req.session.userId, user.full_name, text], function() {
            const comment = { id: this.lastID, photo_id: parseInt(req.params.id), user_id: req.session.userId, text, current_fullname: user.full_name, user_avatar: user.profile_pic };
            io.emit('new_comment', comment);
            res.json({ success: true, id: this.lastID });
        });
    });
});

// MESSAGES (Temps Réel)
app.get('/api/messages', isAuthenticated, (req, res) => {
    db.all(`SELECT m.*, u.profile_pic AS user_avatar, u.full_name AS current_fullname FROM (SELECT * FROM global_messages ORDER BY created_at DESC LIMIT 50) m LEFT JOIN users u ON m.user_id = u.id ORDER BY m.created_at ASC`, [], (err, rows) => res.json(rows || []));
});

app.post('/api/messages', isAuthenticated, (req, res) => {
    const text = sanitize(req.body.text, 1000);
    db.get('SELECT full_name, profile_pic FROM users WHERE id = ?', [req.session.userId], (err, user) => {
        db.run('INSERT INTO global_messages (user_id, user_name, text) VALUES (?, ?, ?)', [req.session.userId, user.full_name, text], function() {
            const msg = { id: this.lastID, user_id: req.session.userId, text, current_fullname: user.full_name, user_avatar: user.profile_pic };
            io.emit('new_message', msg);
            res.json({ success: true });
        });
    });
});

// ============ AUTRES ROUTES (Audios, Stories) ============
app.get('/api/audios', isAuthenticated, (req, res) => {
    db.all(`SELECT a.*, u.profile_pic AS user_avatar, u.full_name AS current_fullname FROM audios a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_date DESC LIMIT 50`, [], (err, rows) => res.json(rows || []));
});
app.post('/api/audios', isAuthenticated, upload.single('audio'), (req, res) => {
    db.run('INSERT INTO audios (file_url, title, artist, user_id, user_name) VALUES (?, ?, ?, ?, ?)', [`/audios/${req.file.filename}`, sanitize(req.body.title), sanitize(req.body.artist), req.session.userId, ''], function() { res.json({ id: this.lastID }); });
});
app.get('/api/stories', isAuthenticated, (req, res) => {
    db.all(`SELECT s.*, u.profile_pic AS user_avatar, u.full_name AS current_fullname FROM stories s LEFT JOIN users u ON s.user_id = u.id WHERE s.expires_at > datetime('now') ORDER BY s.created_at DESC`, [], (err, rows) => res.json(rows || []));
});
app.post('/api/stories', isAuthenticated, upload.single('story'), (req, res) => {
    db.run(`INSERT INTO stories (image_url, caption, user_id, expires_at) VALUES (?, ?, ?, datetime('now', '+24 hours'))`, [`/stories/${req.file.filename}`, sanitize(req.body.caption), req.session.userId], function() { res.json({ id: this.lastID }); });
});

// Serve React
app.get('*', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    fs.existsSync(indexPath) ? res.sendFile(indexPath) : res.status(404).send('public/index.html introuvable');
});

// FIX: HttpServer remplace app pour Socket.io
httpServer.listen(PORT, () => {
    console.log(`🚀 SnapQuest V3 (DarkMods Social Network) Démarré Sur Le Port ${PORT}`);
});