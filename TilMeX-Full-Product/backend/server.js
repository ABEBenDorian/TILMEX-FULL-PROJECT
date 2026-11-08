// TilMeX - Production Server with Full Security
require('dotenv').config();

const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const sanitizeHtml = require('sanitize-html');
const { body, validationResult } = require('express-validator');
const compression = require('compression');
const fs = require('fs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: process.env.CLIENT_URL || "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === 'production' ? (() => { throw new Error('JWT_SECRET must be set in production.'); })() : 'tilmex-local-dev-jwt-secret-change-before-deploy');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// ==================== SECURITY MIDDLEWARE ====================

// 1. Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://*.kaspersky-labs.com"],
            scriptSrcAttr: ["'unsafe-inline'"], // <-- Add this line to allow onclick/onsubmit handlers
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "ws:", "wss:"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// 2. CORS configuration
app.use(cors({
    origin: process.env.CLIENT_URL || '*',
    credentials: true,
    optionsSuccessStatus: 200
}));

// 3. Compression for better performance
app.use(compression());

// 4. Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Session management
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: process.env.SESSION_DB_DIR || path.dirname(process.env.DB_PATH || './tilmex.db')
    }),
    secret: process.env.SESSION_SECRET || (process.env.NODE_ENV === 'production' ? (() => { throw new Error('SESSION_SECRET must be set in production.'); })() : 'tilmex-local-dev-session-secret-change-before-deploy'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    }
}));

// 6. Rate limiting for all API routes
const apiLimiter = rateLimit({
    windowMs: (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000,
    max: process.env.RATE_LIMIT_MAX || 100,
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', apiLimiter);

// 7. Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many login attempts, please try again after 15 minutes.'
});
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// ==================== DATABASE SETUP ====================

// Ensure directories exist
const dbDir = path.dirname(process.env.DB_PATH || './tilmex.db');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

const logDir = path.dirname(process.env.LOG_FILE || './logs/app.log');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Simple logging function
const logger = {
    info: (msg) => console.log(`[INFO] ${new Date().toISOString()}: ${msg}`),
    error: (msg) => console.error(`[ERROR] ${new Date().toISOString()}: ${msg}`),
    warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()}: ${msg}`)
};

// Database connection
const db = new sqlite3.Database(process.env.DB_PATH || './tilmex.db', (err) => {
    if (err) {
        logger.error('Database connection error: ' + err.message);
    } else {
        logger.info('Connected to SQLite database');
    }
});

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password TEXT NOT NULL,
        display_name TEXT,
        avatar TEXT,
        bio TEXT,
        phone TEXT,
        online BOOLEAN DEFAULT 0,
        last_seen DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        message_type TEXT DEFAULT 'text',
        file_url TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        read BOOLEAN DEFAULT 0,
        delivered BOOLEAN DEFAULT 0,
        edited BOOLEAN DEFAULT 0,
        deleted BOOLEAN DEFAULT 0,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        last_message TEXT,
        last_message_time DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user1_id, user2_id),
        FOREIGN KEY (user1_id) REFERENCES users(id),
        FOREIGN KEY (user2_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS blocked_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blocker_id INTEGER NOT NULL,
        blocked_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (blocker_id) REFERENCES users(id),
        FOREIGN KEY (blocked_id) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS message_reactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        reaction TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (message_id) REFERENCES messages(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Social feed tables (safe to add to an existing database)
    db.run(`CREATE TABLE IF NOT EXISTS social_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        caption TEXT DEFAULT '',
        media_data TEXT,
        media_type TEXT DEFAULT 'text',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS social_likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        reaction TEXT NOT NULL DEFAULT 'like',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(post_id, user_id),
        FOREIGN KEY (post_id) REFERENCES social_posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS social_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES social_posts(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS social_follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        follower_id INTEGER NOT NULL,
        followed_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(follower_id, followed_id),
        CHECK(follower_id != followed_id),
        FOREIGN KEY (follower_id) REFERENCES users(id),
        FOREIGN KEY (followed_id) REFERENCES users(id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS social_favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, post_id),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (post_id) REFERENCES social_posts(id)
    )`);

    // Create indexes for better performance
    db.run('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_conversations_users ON conversations(user1_id, user2_id)');
});

// ==================== HELPER FUNCTIONS ====================

// Sanitize user input
function sanitizeInput(text) {
    return sanitizeHtml(text, {
        allowedTags: [],
        allowedAttributes: {},
        allowedSchemes: []
    });
}

// Generate JWT token
function generateToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Token expired' });
            }
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Check if user is blocked
function isBlocked(userId, otherUserId) {
    return new Promise((resolve) => {
        db.get(
            'SELECT * FROM blocked_users WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)',
            [userId, otherUserId, otherUserId, userId],
            (err, row) => {
                resolve(!!row);
            }
        );
    });
}

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Register using only a display name and password. Display names are case-insensitively unique.
app.post('/api/register', [
    body('displayName').trim().isLength({ min: 1, max: 50 }).withMessage('Display name must be 1–50 characters'),
    body('password').isLength({ min: 6, max: 72 }).withMessage('Password must be 6–72 characters')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const displayName = sanitizeInput(String(req.body.displayName || '').trim());
    const password = String(req.body.password || '');
    if (!displayName) return res.status(400).json({ error: 'Choose a display name.' });
    const username = displayName;
    try {
        const existing = await new Promise((resolve, reject) => db.get(
            'SELECT id FROM users WHERE lower(display_name) = lower(?) OR lower(username) = lower(?)',
            [displayName, displayName], (err, row) => err ? reject(err) : resolve(row)
        ));
        if (existing) return res.status(409).json({ error: 'That display name is already taken. Choose another.' });
        const hashedPassword = await bcrypt.hash(password, 12);
        const initials = displayName.slice(0, 2).toUpperCase().replace(/[<>&"']/g, '');
        const avatarSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="160" height="160"><rect width="100%" height="100%" rx="80" fill="#253b64"/><text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="Arial" font-size="54" fill="white">${initials}</text></svg>`;
        const avatar = 'data:image/svg+xml;base64,' + Buffer.from(avatarSvg).toString('base64');
        const result = await new Promise((resolve, reject) => db.run(
            'INSERT INTO users (username, email, password, display_name, avatar, phone) VALUES (?, NULL, ?, ?, ?, NULL)',
            [username, hashedPassword, displayName, avatar], function(err) { if (err) reject(err); else resolve({ id: this.lastID }); }
        ));
        const token = generateToken({ id: result.id, username });
        const user = { id: result.id, username, email: null, displayName, avatar, bio: '', phone: null };
        logger.info(`New user registered: ${displayName} (ID: ${result.id})`);
        return res.status(201).json({ success: true, token, user });
    } catch (error) {
        if (String(error.message).includes('UNIQUE constraint failed')) return res.status(409).json({ error: 'That display name is already taken.' });
        logger.error('Registration error: ' + error.message);
        return res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login with display name + password; old usernames remain accepted for migrated accounts.
app.post('/api/login', [
    body('username').trim().isLength({ min: 1, max: 50 }).withMessage('Display name is required'),
    body('password').isLength({ min: 1, max: 72 }).withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const displayName = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    try {
        const user = await new Promise((resolve, reject) => db.get(
            'SELECT * FROM users WHERE lower(display_name) = lower(?) OR lower(username) = lower(?) ORDER BY id DESC LIMIT 1',
            [displayName, displayName], (err, row) => err ? reject(err) : resolve(row)
        ));
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Incorrect display name or password.' });
        const token = generateToken({ id: user.id, username: user.username });
        db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
        const userData = { id:user.id, username:user.username, email:user.email||null, displayName:user.display_name||user.username, avatar:user.avatar, bio:user.bio||'', phone:user.phone||null };
        logger.info(`User logged in: ${displayName} (ID: ${user.id})`);
        return res.json({ success:true, token, user:userData });
    } catch (error) {
        logger.error('Login error: ' + error.message);
        return res.status(500).json({ error: 'Server error during login' });
    }
});

// Get all users (for chat list)
app.get('/api/users', authenticateToken, async (req, res) => {
    try {
        const users = await new Promise((resolve, reject) => {
            db.all(
                `SELECT id, username, display_name, avatar, bio, online, last_seen 
                 FROM users 
                 WHERE id != ? 
                 ORDER BY display_name ASC`,
                [req.user.id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        // Filter out blocked users
        const filteredUsers = [];
        for (const user of users) {
            const blocked = await isBlocked(req.user.id, user.id);
            if (!blocked) {
                filteredUsers.push(user);
            }
        }

        res.json(filteredUsers);
    } catch (error) {
        logger.error('Get users error: ' + error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get conversations
app.get('/api/conversations', authenticateToken, (req, res) => {
    db.all(
        `SELECT c.*, u.display_name, u.avatar, u.online,
         (SELECT COUNT(*) FROM messages m WHERE m.sender_id = c.user2_id AND m.receiver_id = c.user1_id AND m.read = 0) as unread_count
         FROM conversations c
         JOIN users u ON (u.id = c.user2_id AND c.user1_id = ?) OR (u.id = c.user1_id AND c.user2_id = ?)
         WHERE c.user1_id = ? OR c.user2_id = ?
         ORDER BY c.last_message_time DESC`,
        [req.user.id, req.user.id, req.user.id, req.user.id],
        (err, rows) => {
            if (err) {
                logger.error('Get conversations error: ' + err.message);
                return res.status(500).json({ error: 'Server error' });
            }
            res.json(rows);
        }
    );
});

// Get messages with a specific user
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    const otherUserId = parseInt(req.params.userId);

    // Check if blocked
    const blocked = await isBlocked(req.user.id, otherUserId);
    if (blocked) {
        return res.status(403).json({ error: 'Unable to retrieve messages' });
    }

    try {
        const messages = await new Promise((resolve, reject) => {
            db.all(
                `SELECT * FROM messages 
                 WHERE (sender_id = ? AND receiver_id = ?) 
                 OR (sender_id = ? AND receiver_id = ?)
                 ORDER BY timestamp ASC
                 LIMIT 500`,
                [req.user.id, otherUserId, otherUserId, req.user.id],
                (err, rows) => {
                    if (err) reject(err);
                    resolve(rows);
                }
            );
        });

        // Mark messages as read
        db.run(
            'UPDATE messages SET read = 1 WHERE sender_id = ? AND receiver_id = ? AND read = 0',
            [otherUserId, req.user.id]
        );

        res.json(messages);
    } catch (error) {
        logger.error('Get messages error: ' + error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Send a message
app.post('/api/messages', authenticateToken, [
    body('receiverId').isInt().withMessage('Valid receiver ID required'),
    body('content').trim().isLength({ min: 1, max: 4000 }).withMessage('Message must be 1-4000 characters')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { receiverId, content } = req.body;

    // Sanitize content
    const sanitizedContent = sanitizeInput(content);

    // Check if blocked
    const blocked = await isBlocked(req.user.id, receiverId);
    if (blocked) {
        return res.status(403).json({ error: 'Unable to send message' });
    }

    try {
        const result = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                [req.user.id, receiverId, sanitizedContent],
                function(err) {
                    if (err) reject(err);
                    resolve({ id: this.lastID });
                }
            );
        });

        // Update or create conversation
        await new Promise((resolve, reject) => {
            db.run(
                `INSERT INTO conversations (user1_id, user2_id, last_message, last_message_time)
                 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                 ON CONFLICT(user1_id, user2_id) 
                 DO UPDATE SET last_message = ?, last_message_time = CURRENT_TIMESTAMP`,
                [Math.min(req.user.id, receiverId), Math.max(req.user.id, receiverId), sanitizedContent, sanitizedContent],
                (err) => {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        const message = {
            id: result.id,
            sender_id: req.user.id,
            receiver_id: receiverId,
            content: sanitizedContent,
            timestamp: new Date().toISOString(),
            read: false,
            delivered: false
        };

        // Emit to receiver
        io.to(`user_${receiverId}`).emit('new_message', message);
        // Emit back to sender
        io.to(`user_${req.user.id}`).emit('message_sent', message);

        logger.info(`Message sent: User ${req.user.id} to User ${receiverId}`);

        res.status(201).json(message);
    } catch (error) {
        logger.error('Send message error: ' + error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// Block user
app.post('/api/block/:userId', authenticateToken, (req, res) => {
    const userIdToBlock = parseInt(req.params.userId);

    db.run(
        'INSERT OR IGNORE INTO blocked_users (blocker_id, blocked_id) VALUES (?, ?)',
        [req.user.id, userIdToBlock],
        (err) => {
            if (err) {
                logger.error('Block user error: ' + err.message);
                return res.status(500).json({ error: 'Server error' });
            }
            res.json({ success: true, message: 'User blocked' });
        }
    );
});

// Unblock user
app.post('/api/unblock/:userId', authenticateToken, (req, res) => {
    const userIdToUnblock = parseInt(req.params.userId);

    db.run(
        'DELETE FROM blocked_users WHERE blocker_id = ? AND blocked_id = ?',
        [req.user.id, userIdToUnblock],
        (err) => {
            if (err) {
                logger.error('Unblock user error: ' + err.message);
                return res.status(500).json({ error: 'Server error' });
            }
            res.json({ success: true, message: 'User unblocked' });
        }
    );
});

// Update user profile
app.put('/api/profile', authenticateToken, [
    body('displayName').optional().trim().isLength({ max: 50 }),
    body('bio').optional().trim().isLength({ max: 200 }),
    body('phone').optional().trim().isLength({ max: 20 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { displayName, bio, phone } = req.body;

    db.run(
        'UPDATE users SET display_name = COALESCE(?, display_name), bio = COALESCE(?, bio), phone = COALESCE(?, phone), updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [displayName, bio, phone, req.user.id],
        (err) => {
            if (err) {
                logger.error('Update profile error: ' + err.message);
                return res.status(500).json({ error: 'Server error' });
            }
            res.json({ success: true, message: 'Profile updated' });
        }
    );
});

// Delete account
app.delete('/api/account', authenticateToken, (req, res) => {
    db.run('DELETE FROM users WHERE id = ?', [req.user.id], (err) => {
        if (err) {
            logger.error('Delete account error: ' + err.message);
            return res.status(500).json({ error: 'Server error' });
        }
        logger.info(`User deleted account: ${req.user.id}`);
        res.json({ success: true, message: 'Account deleted' });
    });
});

// ==================== SOCKET.IO ====================

// Socket authentication middleware
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error'));
    }

    try {
        const user = jwt.verify(token, JWT_SECRET);
        socket.userId = user.id;
        socket.username = user.username;
        next();
    } catch (err) {
        next(new Error('Authentication error'));
    }
});

// Socket connection handler
io.on('connection', (socket) => {
    logger.info(`User connected: ${socket.username} (ID: ${socket.userId})`);

    // Update user online status
    db.run('UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);

    // Broadcast online status
    socket.broadcast.emit('user_online', { userId: socket.userId, online: true });

    // Join user's room
    socket.join(`user_${socket.userId}`);

    // Handle private message
    socket.on('private_message', async (data) => {
        const { receiverId, content } = data;

        // Sanitize content
        const sanitizedContent = sanitizeInput(content);

        // Check if blocked
        const blocked = await isBlocked(socket.userId, receiverId);
        if (blocked) {
            socket.emit('error', { message: 'Unable to send message' });
            return;
        }

        // Save message to database
        db.run(
            'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
            [socket.userId, receiverId, sanitizedContent],
            function(err) {
                if (err) {
                    logger.error('Socket message save error: ' + err.message);
                    socket.emit('error', { message: 'Failed to send message' });
                    return;
                }

                const messageData = {
                    id: this.lastID,
                    senderId: socket.userId,
                    receiverId,
                    content: sanitizedContent,
                    timestamp: new Date().toISOString(),
                    read: false,
                    delivered: true
                };

                // Send to receiver
                io.to(`user_${receiverId}`).emit('new_message', messageData);
                // Send back to sender
                socket.emit('message_sent', messageData);

                // Update conversation
                db.run(
                    `INSERT INTO conversations (user1_id, user2_id, last_message, last_message_time)
                     VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                     ON CONFLICT(user1_id, user2_id) 
                     DO UPDATE SET last_message = ?, last_message_time = CURRENT_TIMESTAMP`,
                    [Math.min(socket.userId, receiverId), Math.max(socket.userId, receiverId), sanitizedContent, sanitizedContent]
                );
            }
        );
    });

    // WebRTC call signalling. Media travels peer-to-peer; this server relays setup messages only.
    socket.on('call:invite', data => {
        const to = Number(data && data.to);
        if (!Number.isInteger(to) || to < 1 || to === Number(socket.userId) || !data.offer) return;
        io.to(`user_${to}`).emit('call:incoming', { from:socket.userId, username:socket.username, callType:data.callType==='audio'?'audio':'video', offer:data.offer });
    });
    socket.on('call:answer', data => {
        const to = Number(data && data.to);
        if (Number.isInteger(to) && to > 0 && data.answer) io.to(`user_${to}`).emit('call:answered', { from:socket.userId, answer:data.answer });
    });
    socket.on('call:ice', data => {
        const to = Number(data && data.to);
        if (Number.isInteger(to) && to > 0 && data.candidate) io.to(`user_${to}`).emit('call:ice', { from:socket.userId, candidate:data.candidate });
    });
    socket.on('call:decline', data => {
        const to = Number(data && data.to);
        if (Number.isInteger(to) && to > 0) io.to(`user_${to}`).emit('call:declined', { from:socket.userId });
    });
    socket.on('call:end', data => {
        const to = Number(data && data.to);
        if (Number.isInteger(to) && to > 0) io.to(`user_${to}`).emit('call:ended', { from:socket.userId });
    });

    // Handle typing indicator
    socket.on('typing', (data) => {
        socket.to(`user_${data.receiverId}`).emit('user_typing', {
            userId: socket.userId,
            username: socket.username,
            isTyping: data.isTyping
        });
    });

    // Handle read receipts
    socket.on('mark_read', (data) => {
        db.run(
            'UPDATE messages SET read = 1 WHERE sender_id = ? AND receiver_id = ? AND read = 0',
            [data.senderId, socket.userId],
            (err) => {
                if (!err) {
                    io.to(`user_${data.senderId}`).emit('messages_read', { 
                        userId: socket.userId,
                        readAt: new Date().toISOString()
                    });
                }
            }
        );
    });

    // Handle message deletion
    socket.on('delete_message', (data) => {
        db.run(
            'UPDATE messages SET deleted = 1 WHERE id = ? AND sender_id = ?',
            [data.messageId, socket.userId],
            (err) => {
                if (!err) {
                    io.to(`user_${data.receiverId}`).emit('message_deleted', {
                        messageId: data.messageId,
                        userId: socket.userId
                    });
                }
            }
        );
    });

    // Handle message editing
    socket.on('edit_message', (data) => {
        const sanitizedContent = sanitizeInput(data.newContent);
        db.run(
            'UPDATE messages SET content = ?, edited = 1 WHERE id = ? AND sender_id = ?',
            [sanitizedContent, data.messageId, socket.userId],
            (err) => {
                if (!err) {
                    io.to(`user_${data.receiverId}`).emit('message_edited', {
                        messageId: data.messageId,
                        newContent: sanitizedContent,
                        userId: socket.userId
                    });
                }
            }
        );
    });

    // Handle message reactions
    socket.on('message_reaction', (data) => {
        db.run(
            'INSERT OR REPLACE INTO message_reactions (message_id, user_id, reaction) VALUES (?, ?, ?)',
            [data.messageId, socket.userId, data.reaction],
            (err) => {
                if (!err) {
                    io.to(`user_${data.receiverId}`).emit('message_reaction_added', {
                        messageId: data.messageId,
                        userId: socket.userId,
                        reaction: data.reaction
                    });
                }
            }
        );
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        logger.info(`User disconnected: ${socket.username} (ID: ${socket.userId})`);
        db.run('UPDATE users SET online = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);
        socket.broadcast.emit('user_offline', { userId: socket.userId, online: false });
    });
});

// ==================== SOCIAL FEED API ====================
// Media is accepted as a data URL (image/video). Keep uploads reasonably small;
// for production-scale media, use object storage instead of storing data URLs in SQLite.
function validMediaData(value) {
    if (typeof value !== 'string' || value.length > 8 * 1024 * 1024) return false;
    return /^data:(image\/(jpeg|png|gif|webp)|video\/(mp4|webm|quicktime)|audio\/(webm|ogg|mp4|mpeg|wav)(?:;codecs=[A-Za-z0-9._-]+)?);base64,[A-Za-z0-9+/=\r\n]+$/.test(value);
}

app.get('/api/social/feed', authenticateToken, (req, res) => {
    const sql = `SELECT p.id, p.user_id AS userId, p.caption, p.media_data AS mediaData,
        p.media_type AS mediaType, p.created_at AS createdAt,
        u.username, u.display_name AS displayName, u.avatar,
        (SELECT COUNT(*) FROM social_likes l WHERE l.post_id = p.id AND l.reaction = 'like') AS likes,
        (SELECT COUNT(*) FROM social_likes l WHERE l.post_id = p.id AND l.reaction = 'dislike') AS dislikes,
        (SELECT COUNT(*) FROM social_comments c WHERE c.post_id = p.id) AS comments,
        (SELECT reaction FROM social_likes mine WHERE mine.post_id = p.id AND mine.user_id = ?) AS myReaction
        FROM social_posts p JOIN users u ON u.id = p.user_id
        ORDER BY p.created_at DESC LIMIT 100`;
    db.all(sql, [req.user.id], (err, rows) => {
        if (err) { logger.error('Social feed error: ' + err.message); return res.status(500).json({error:'Could not load feed'}); }
        res.json({ success: true, posts: rows });
    });
});

app.post('/api/social/posts', authenticateToken, (req, res) => {
    const caption = typeof req.body.caption === 'string' ? sanitizeInput(req.body.caption).slice(0, 2200) : '';
    const mediaData = req.body.mediaData || null;
    let mediaType = 'text';
    if (mediaData) {
        if (!validMediaData(mediaData)) return res.status(400).json({error:'Unsupported media or file too large (maximum about 6 MB).'});
        mediaType = mediaData.startsWith('data:video/') ? 'video' : (mediaData.startsWith('data:audio/') ? 'audio' : 'image');
    }
    if (!caption.trim() && !mediaData) return res.status(400).json({error:'Add a caption or choose a photo/video.'});
    db.run('INSERT INTO social_posts (user_id, caption, media_data, media_type) VALUES (?, ?, ?, ?)',
        [req.user.id, caption, mediaData, mediaType], function(err) {
            if (err) { logger.error('Create social post error: ' + err.message); return res.status(500).json({error:'Could not create post'}); }
            db.get(`SELECT p.id, p.user_id AS userId, p.caption, p.media_data AS mediaData, p.media_type AS mediaType,
                p.created_at AS createdAt, u.username, u.display_name AS displayName, u.avatar,
                0 AS likes, 0 AS dislikes, 0 AS comments, NULL AS myReaction
                FROM social_posts p JOIN users u ON u.id = p.user_id WHERE p.id = ?`, [this.lastID], (getErr, post) => {
                if (getErr) return res.status(500).json({error:'Post created but could not be returned'});
                io.emit('social_post_created', post);
                res.status(201).json({success:true, post});
            });
        });
});

app.post('/api/social/posts/:postId/reaction', authenticateToken, (req, res) => {
    const postId = Number(req.params.postId);
    const reaction = req.body.reaction;
    if (!Number.isInteger(postId) || postId < 1 || !['like','dislike'].includes(reaction)) return res.status(400).json({error:'Invalid reaction'});
    db.get('SELECT id FROM social_posts WHERE id = ?', [postId], (findErr, post) => {
        if (findErr || !post) return res.status(404).json({error:'Post not found'});
        db.get('SELECT reaction FROM social_likes WHERE post_id = ? AND user_id = ?', [postId, req.user.id], (err, existing) => {
            if (err) return res.status(500).json({error:'Could not save reaction'});
            if (existing && existing.reaction === reaction) {
                db.run('DELETE FROM social_likes WHERE post_id = ? AND user_id = ?', [postId, req.user.id], e => {
                    if (e) return res.status(500).json({error:'Could not remove reaction'});
                    res.json({success:true, reaction:null});
                });
            } else {
                db.run(`INSERT INTO social_likes (post_id, user_id, reaction) VALUES (?, ?, ?)
                    ON CONFLICT(post_id, user_id) DO UPDATE SET reaction = excluded.reaction`, [postId, req.user.id, reaction], e => {
                    if (e) return res.status(500).json({error:'Could not save reaction'});
                    res.json({success:true, reaction});
                });
            }
        });
    });
});

app.get('/api/social/posts/:postId/comments', authenticateToken, (req, res) => {
    const postId = Number(req.params.postId);
    db.all(`SELECT c.id, c.post_id AS postId, c.content, c.created_at AS createdAt,
        u.id AS userId, u.username, u.display_name AS displayName, u.avatar
        FROM social_comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.created_at ASC`, [postId], (err, rows) => {
        if (err) return res.status(500).json({error:'Could not load comments'});
        res.json({success:true, comments:rows});
    });
});

app.post('/api/social/posts/:postId/comments', authenticateToken, (req, res) => {
    const postId = Number(req.params.postId);
    const content = typeof req.body.content === 'string' ? sanitizeInput(req.body.content).trim().slice(0, 1000) : '';
    if (!Number.isInteger(postId) || postId < 1 || !content) return res.status(400).json({error:'Write a comment first'});
    db.run('INSERT INTO social_comments (post_id, user_id, content) SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM social_posts WHERE id = ?)',
        [postId, req.user.id, content, postId], function(err) {
            if (err) return res.status(500).json({error:'Could not add comment'});
            if (!this.changes) return res.status(404).json({error:'Post not found'});
            db.get(`SELECT c.id, c.post_id AS postId, c.content, c.created_at AS createdAt,
                u.id AS userId, u.username, u.display_name AS displayName, u.avatar
                FROM social_comments c JOIN users u ON u.id = c.user_id WHERE c.id = ?`, [this.lastID], (e, comment) => {
                if (e) return res.status(500).json({error:'Comment saved but could not be returned'});
                res.status(201).json({success:true, comment});
            });
        });
});

app.post('/api/social/users/:userId/follow', authenticateToken, (req, res) => {
    const followedId = Number(req.params.userId);
    if (!Number.isInteger(followedId) || followedId < 1 || followedId === req.user.id) return res.status(400).json({error:'Invalid user'});
    db.get('SELECT id FROM users WHERE id = ?', [followedId], (findErr, user) => {
        if (findErr || !user) return res.status(404).json({error:'User not found'});
        db.get('SELECT id FROM social_follows WHERE follower_id = ? AND followed_id = ?', [req.user.id, followedId], (err, existing) => {
            if (err) return res.status(500).json({error:'Could not update follow'});
            if (existing) {
                db.run('DELETE FROM social_follows WHERE follower_id = ? AND followed_id = ?', [req.user.id, followedId], e => {
                    if (e) return res.status(500).json({error:'Could not unfollow user'});
                    res.json({success:true, following:false});
                });
            } else {
                db.run('INSERT INTO social_follows (follower_id, followed_id) VALUES (?, ?)', [req.user.id, followedId], e => {
                    if (e) return res.status(500).json({error:'Could not follow user'});
                    res.json({success:true, following:true});
                });
            }
        });
    });
});

app.get('/api/social/users/:userId/follow-status', authenticateToken, (req, res) => {
    const followedId = Number(req.params.userId);
    db.get('SELECT id FROM social_follows WHERE follower_id = ? AND followed_id = ?', [req.user.id, followedId], (err, row) => {
        if (err) return res.status(500).json({error:'Could not read follow status'});
        res.json({success:true, following:!!row});
    });
});

app.get('/api/social/users/:userId/stats', authenticateToken, (req, res) => {
    const userId = Number(req.params.userId);
    db.get(`SELECT
        (SELECT COUNT(*) FROM social_posts WHERE user_id = ?) AS posts,
        (SELECT COUNT(*) FROM social_follows WHERE followed_id = ?) AS followers,
        (SELECT COUNT(*) FROM social_follows WHERE follower_id = ?) AS following`, [userId,userId,userId], (err, stats) => {
        if (err) return res.status(500).json({error:'Could not load profile stats'});
        res.json({success:true, stats});
    });
});

// Saved posts / favourites.
app.get('/api/social/favorites', authenticateToken, (req, res) => {
    const sql = `SELECT p.id, p.user_id AS userId, p.caption, p.media_data AS mediaData,
        p.media_type AS mediaType, p.created_at AS createdAt, u.username,
        u.display_name AS displayName, u.avatar,
        (SELECT COUNT(*) FROM social_likes l WHERE l.post_id=p.id AND l.reaction='like') AS likes,
        (SELECT COUNT(*) FROM social_comments c WHERE c.post_id=p.id) AS comments,
        (SELECT reaction FROM social_likes mine WHERE mine.post_id=p.id AND mine.user_id=?) AS myReaction,
        1 AS isFavorite
        FROM social_favorites f JOIN social_posts p ON p.id=f.post_id JOIN users u ON u.id=p.user_id
        WHERE f.user_id=? ORDER BY f.created_at DESC LIMIT 100`;
    db.all(sql, [req.user.id, req.user.id], (err, rows) => {
        if (err) return res.status(500).json({error:'Could not load favorites'});
        res.json({success:true, posts:rows});
    });
});
app.post('/api/social/posts/:postId/favorite', authenticateToken, (req, res) => {
    const postId=Number(req.params.postId);
    if (!Number.isInteger(postId)||postId<1) return res.status(400).json({error:'Invalid post'});
    db.get('SELECT id FROM social_favorites WHERE user_id=? AND post_id=?',[req.user.id,postId],(err,row)=>{
        if(err) return res.status(500).json({error:'Could not update favorite'});
        if(row){
            db.run('DELETE FROM social_favorites WHERE user_id=? AND post_id=?',[req.user.id,postId],e=>{
                if(e) return res.status(500).json({error:'Could not remove favorite'});
                res.json({success:true,favorite:false});
            });
        } else {
            db.run('INSERT INTO social_favorites (user_id,post_id) SELECT ?,? WHERE EXISTS (SELECT 1 FROM social_posts WHERE id=?)',[req.user.id,postId,postId],function(e){
                if(e) return res.status(500).json({error:'Could not save favorite'});
                if(!this.changes) return res.status(404).json({error:'Post not found'});
                res.json({success:true,favorite:true});
            });
        }
    });
});

app.put('/api/profile/photo', authenticateToken, (req, res) => {
    const photo = req.body.photo;
    if (typeof photo !== 'string' || photo.length > 5 * 1024 * 1024 || !/^data:image\/(jpeg|png|gif|webp);base64,[A-Za-z0-9+/=\r\n]+$/.test(photo)) {
        return res.status(400).json({error:'Choose a valid image under about 3.5 MB.'});
    }
    db.run('UPDATE users SET avatar = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [photo, req.user.id], err => {
        if (err) return res.status(500).json({error:'Could not update profile photo'});
        res.json({success:true, avatar:photo});
    });
});

// ==================== STATIC FILES ====================

// Serve static files
const staticAssets = express.static(__dirname, { index:false, dotfiles:'deny', maxAge:process.env.NODE_ENV==='production'?'1h':0 });
const allowedStaticFiles = new Set(['/index.html','/style.css','/script.js','/social-api.js','/icon.svg','/offline-pool.html','/service-worker.js','/manifest.webmanifest']);
app.use((req,res,next)=>allowedStaticFiles.has(req.path)?staticAssets(req,res,next):next());

// SPA fallback
app.get('/', (req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.get('*',(req,res,next)=>{if(req.path.startsWith('/api/')||req.path.startsWith('/socket.io/'))return next();return res.status(404).json({error:'Not found'});});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error: ' + err.message);
    console.error(err.stack);
    
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'production' ? 'Something went wrong' : err.message
    });
});

// ==================== START SERVER ====================

server.listen(PORT, () => {
    logger.info(`🚀 TilMeX server running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`Access locally: http://localhost:${PORT}`);
    
    if (process.env.NODE_ENV === 'production') {
        logger.info(`Access from internet: ${process.env.CLIENT_URL || 'Your domain'}`);
    }
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received. Shutting down gracefully...');
    db.close();
    server.close(() => {
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    logger.info('SIGINT received. Shutting down gracefully...');
    db.close();
    server.close(() => {
        process.exit(0);
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    logger.error('Uncaught exception: ' + err.message);
    console.error(err.stack);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled rejection at:', promise, 'reason:', reason);
});
