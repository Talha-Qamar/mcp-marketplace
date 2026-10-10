const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const { initDb } = require('./src/db');
const authRoutes = require('./src/routes/auth');
const apiRoutes = require('./src/routes/api');
const mcsRoutes = require('./src/routes/mcpsecure');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'mcp_marketplace_secret_key_123!@#',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
    }
}));

// Serve static files
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Mount routes
app.use('/api/auth', authRoutes);
app.use('/api', apiRoutes);
app.use('/api/mcs', mcsRoutes);

// Serve specific HTML pages (existing + MCS additions)
const pages = [
    'servers', 'server-detail', 'publish', 'clients', 'categories',
    'login', 'register', 'profile',
    // MCP Secure POC pages (old pages kept for direct-link compatibility)
    'scan', 'attestations', 'watcher', 'verifier',
    // New restructured pages
    'admin', 'verify',
];
for (const page of pages) {
    app.get(`/${page}`, (req, res) => {
        const pagePath = path.join(publicPath, `${page}.html`);
        if (fs.existsSync(pagePath)) {
            res.sendFile(pagePath);
        } else {
            res.status(404).send('Page not found');
        }
    });
    app.get(`/${page}.html`, (req, res) => {
        const pagePath = path.join(publicPath, `${page}.html`);
        if (fs.existsSync(pagePath)) {
            res.sendFile(pagePath);
        } else {
            res.status(404).send('Page not found');
        }
    });
}

// Fallback to index.html for root
app.get('/', (req, res) => {
    res.sendFile(path.join(publicPath, 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Initialize database then start server
async function start() {
    try {
        await initDb();
        console.log('Database initialized successfully.');

        // Seed MCP Secure demo data (idempotent — safe to run every startup)
        try {
            const { seedMcpSecure } = require('./src/mcpsecure/seed');
            await seedMcpSecure();
        } catch (e) {
            console.warn('[MCS] Seed warning (non-fatal):', e.message);
        }

        app.listen(PORT, () => {
            console.log(`\n🚀 MCP Marketplace server running on http://localhost:${PORT}`);
            console.log(`   🔒 MCP Secure POC layer active`);
            console.log(`   📋 /scan  📊 /attestations  👁 /watcher  🔍 /verifier\n`);
        });
    } catch (error) {
        console.error('Failed to initialize database:', error);
        process.exit(1);
    }
}

start();
