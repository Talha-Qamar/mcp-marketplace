function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        req.user = { id: req.session.userId, username: req.session.username };
        return next();
    }
    return res.status(401).json({ error: 'Unauthorized: Please log in first' });
}

function optionalAuth(req, res, next) {
    if (req.session && req.session.userId) {
        req.user = { id: req.session.userId, username: req.session.username };
    }
    next();
}

/** Admin-only routes (review queue, decisions). The role is read from the DB on every call. */
function requireAdmin(req, res, next) {
    if (!(req.session && req.session.userId)) {
        return res.status(401).json({ error: 'Unauthorized: Please log in first' });
    }
    const { oneRow } = require('../db');
    const user = oneRow(`SELECT id, username, role FROM users WHERE id = ?`, [req.session.userId]);
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin role required' });
    }
    req.user = { id: user.id, username: user.username, role: user.role };
    return next();
}

module.exports = { requireAuth, optionalAuth, requireAdmin };
