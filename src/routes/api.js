const express = require('express');
const db = require('../db');
const { requireAuth, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// Stats
router.get('/stats', (req, res) => {
    try {
        const stats = db.getStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

// Categories
router.get('/categories', (req, res) => {
    try {
        const categories = db.getCategories();
        res.json(categories);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
});

router.get('/categories/:slug', (req, res) => {
    try {
        const category = db.getCategoryBySlug(req.params.slug);
        if (!category) {
            return res.status(404).json({ error: 'Category not found' });
        }
        res.json(category);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch category' });
    }
});

// Tags
router.get('/tags', (req, res) => {
    try {
        const tags = db.getTags();
        res.json(tags);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch tags' });
    }
});

// Clients
router.get('/clients', (req, res) => {
    try {
        const clients = db.getClients();
        res.json(clients);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch clients' });
    }
});

// Servers
router.get('/servers', (req, res) => {
    try {
        const filters = {
            q: req.query.q,
            category: req.query.category,
            language: req.query.language,
            hosting: req.query.hosting,
            sort: req.query.sort,
            page: req.query.page,
            limit: req.query.limit
        };
        const servers = db.getServers(filters);
        res.json(servers);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch servers' });
    }
});

router.get('/servers/:slug', (req, res) => {
    try {
        const server = db.getServerBySlug(req.params.slug);
        if (!server) {
            return res.status(404).json({ error: 'Server not found' });
        }
        res.json(server);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch server' });
    }
});

// Create server
router.post('/servers', requireAuth, (req, res) => {
    try {
        const data = { ...req.body, author_id: req.user.id };
        // Basic validation
        if (!data.name || !data.slug || !data.category_id) {
            return res.status(400).json({ error: 'Name, slug, and category_id are required' });
        }
        
        // Check for existing slug
        const existing = db.getServerBySlug(data.slug);
        if (existing) {
            return res.status(400).json({ error: 'Server with this slug already exists' });
        }

        const newServer = db.createServer(data);
        res.status(201).json(newServer);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to create server' });
    }
});

// Update server
router.put('/servers/:slug', requireAuth, (req, res) => {
    try {
        const server = db.getServerBySlug(req.params.slug);
        if (!server) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        // Check ownership
        if (server.author_id !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to update this server' });
        }

        const updatedServer = db.updateServer(req.params.slug, req.body);
        res.json(updatedServer);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to update server' });
    }
});

// Delete server
router.delete('/servers/:slug', requireAuth, (req, res) => {
    try {
        const server = db.getServerBySlug(req.params.slug);
        if (!server) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        // Check ownership
        if (server.author_id !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to delete this server' });
        }

        const success = db.deleteServer(req.params.slug);
        if (success) {
            res.json({ message: 'Server deleted successfully' });
        } else {
            res.status(500).json({ error: 'Failed to delete server' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to delete server' });
    }
});

// Install tracking
router.post('/servers/:slug/install', optionalAuth, (req, res) => {
    try {
        const server = db.getServerBySlug(req.params.slug);
        if (!server) {
            return res.status(404).json({ error: 'Server not found' });
        }

        const result = db.trackInstall(server.id, {
            user_id: req.user ? req.user.id : null,
            client_type: req.body.client_type
        });

        res.json(result);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to track install' });
    }
});

// Server versions
router.get('/servers/:slug/versions', (req, res) => {
    try {
        const server = db.getServerBySlug(req.params.slug);
        if (!server) {
            return res.status(404).json({ error: 'Server not found' });
        }

        const versions = db.getServerVersions(server.id);
        res.json(versions);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch server versions' });
    }
});

// Server tools
router.get('/servers/:slug/tools', (req, res) => {
    try {
        const server = db.getServerBySlug(req.params.slug);
        if (!server) {
            return res.status(404).json({ error: 'Server not found' });
        }

        const tools = db.getTools(server.id);
        res.json(tools);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch server tools' });
    }
});

// Search
router.get('/search', (req, res) => {
    try {
        const query = req.query.q || '';
        const results = db.searchServers(query);
        res.json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Featured servers
router.get('/featured', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 6;
        const servers = db.getFeaturedServers(limit);
        res.json(servers);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch featured servers' });
    }
});

// Popular servers
router.get('/popular', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 8;
        const servers = db.getPopularServers(limit);
        res.json(servers);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch popular servers' });
    }
});

// Recent servers
router.get('/recent', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 8;
        const servers = db.getRecentServers(limit);
        res.json(servers);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch recent servers' });
    }
});

// User profile
router.get('/users/:username', (req, res) => {
    try {
        const user = db.getUserByUsername(req.params.username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const { password_hash, ...userWithoutPassword } = user;
        const servers = db.getUserServers(user.id);
        res.json({ user: userWithoutPassword, servers });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

module.exports = router;
