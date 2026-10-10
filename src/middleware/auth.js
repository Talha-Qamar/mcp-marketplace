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

module.exports = { requireAuth, optionalAuth };
