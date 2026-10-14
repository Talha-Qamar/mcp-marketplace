/**
 * Marketplace database access (better-sqlite3).
 *
 * A real on-disk SQLite database with WAL journaling: writes go to the file
 * incrementally instead of re-exporting the whole database on every statement
 * (which is what sql.js did). The helper API (allRows / oneRow / runSql) is
 * unchanged, so callers did not change.
 *
 * Schema: database/schema.sql is the full current schema (CREATE ... IF NOT
 * EXISTS). database/migrations.js upgrades databases created by older builds;
 * each migration runs once and is recorded in schema_migrations.
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { runMigrations } = require('../database/migrations');

const dbPath = process.env.MCS_DB_PATH || path.join(__dirname, '..', 'database', 'marketplace.db');

let db = null;

/** better-sqlite3 binds only numbers, strings, bigints, buffers and null. */
function bindable(params) {
    return (params || []).map(v => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v));
}

async function initDb() {
    db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    // Upgrade older databases first, so schema.sql's indexes and new tables
    // never meet a table that is missing a column they reference.
    const applied = runMigrations(db);
    if (applied.length > 0) console.log(`[DB] Applied migration(s): ${applied.join(', ')}`);

    const schemaPath = path.join(__dirname, '..', 'database', 'schema.sql');
    if (fs.existsSync(schemaPath)) db.exec(fs.readFileSync(schemaPath, 'utf8'));
    runMigrations(db); // a brand-new database: record the migrations as applied

    return db;
}

function getDb() {
    if (!db) throw new Error('Database not initialized. Call initDb() first.');
    return db;
}

function allRows(sql, params = []) {
    return db.prepare(sql).all(bindable(params));
}

function oneRow(sql, params = []) {
    return db.prepare(sql).get(bindable(params)) || null;
}

function runSql(sql, params = []) {
    return db.prepare(sql).run(bindable(params));
}

/** Run fn inside one transaction (all-or-nothing). */
function transaction(fn) {
    return db.transaction(fn)();
}

// Catalog visibility (spec §9.1): only servers with an approved scan, plus the
// seeded legacy catalog rows that predate the gate.
const LISTED = `s.listing_status IN ('approved', 'legacy')`;

function getServers(filters = {}) {
    let query = `
        SELECT s.*, u.username as author_username, u.display_name as author_display_name, c.name as category_name, c.slug as category_slug
        FROM servers s
        JOIN users u ON s.author_id = u.id
        JOIN categories c ON s.category_id = c.id
        WHERE ${LISTED}
    `;
    const params = [];

    if (filters.q) {
        query += ` AND (s.name LIKE ? OR s.description LIKE ?)`;
        params.push(`%${filters.q}%`, `%${filters.q}%`);
    }
    if (filters.category) {
        const arr = filters.category.split(',');
        query += ` AND c.slug IN (${arr.map(() => '?').join(',')})`;
        params.push(...arr);
    }
    if (filters.language) {
        const arr = filters.language.split(',');
        query += ` AND s.language IN (${arr.map(() => '?').join(',')})`;
        params.push(...arr);
    }
    if (filters.hosting) {
        const arr = filters.hosting.split(',');
        query += ` AND s.hosting IN (${arr.map(() => '?').join(',')})`;
        params.push(...arr);
    }
    if (filters.security_status) {
        const arr = filters.security_status.split(',');
        query += ` AND s.security_status IN (${arr.map(() => '?').join(',')})`;
        params.push(...arr);
    }

    if (filters.sort) {
        switch (filters.sort) {
            case 'stars': query += ` ORDER BY s.stars DESC`; break;
            case 'installs': query += ` ORDER BY s.install_count DESC`; break;
            case 'newest': query += ` ORDER BY s.created_at DESC`; break;
            case 'updated': query += ` ORDER BY s.updated_at DESC`; break;
            case 'name': query += ` ORDER BY s.name ASC`; break;
            default: query += ` ORDER BY s.stars DESC`;
        }
    } else {
        query += ` ORDER BY s.stars DESC`;
    }

    const page = filters.page ? parseInt(filters.page) : 1;
    const limit = filters.limit ? parseInt(filters.limit) : 20;
    const offset = (page - 1) * limit;

    query += ` LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const servers = allRows(query, params);

    // Attach tags
    for (let server of servers) {
        server.tags = allRows(
            `SELECT t.* FROM tags t JOIN server_tags st ON t.id = st.tag_id WHERE st.server_id = ?`,
            [server.id]
        );
    }

    // Get total count for pagination
    let countQuery = `
        SELECT COUNT(*) as count
        FROM servers s
        JOIN users u ON s.author_id = u.id
        JOIN categories c ON s.category_id = c.id
        WHERE ${LISTED}
    `;
    const countParams = [];
    if (filters.q) {
        countQuery += ` AND (s.name LIKE ? OR s.description LIKE ?)`;
        countParams.push(`%${filters.q}%`, `%${filters.q}%`);
    }
    if (filters.category) {
        const arr = filters.category.split(',');
        countQuery += ` AND c.slug IN (${arr.map(() => '?').join(',')})`;
        countParams.push(...arr);
    }
    if (filters.language) {
        const arr = filters.language.split(',');
        countQuery += ` AND s.language IN (${arr.map(() => '?').join(',')})`;
        countParams.push(...arr);
    }
    if (filters.hosting) {
        const arr = filters.hosting.split(',');
        countQuery += ` AND s.hosting IN (${arr.map(() => '?').join(',')})`;
        countParams.push(...arr);
    }
    if (filters.security_status) {
        const arr = filters.security_status.split(',');
        countQuery += ` AND s.security_status IN (${arr.map(() => '?').join(',')})`;
        countParams.push(...arr);
    }

    const total = oneRow(countQuery, countParams);
    const totalCount = total ? total.count : 0;

    return {
        servers,
        pagination: {
            page,
            limit,
            total: totalCount,
            totalPages: Math.ceil(totalCount / limit)
        }
    };
}

function getServerBySlug(slug) {
    const server = oneRow(`
        SELECT s.*, u.username as author_username, u.display_name as author_display_name, c.name as category_name, c.slug as category_slug
        FROM servers s
        JOIN users u ON s.author_id = u.id
        JOIN categories c ON s.category_id = c.id
        WHERE s.slug = ?
    `, [slug]);

    if (server) {
        server.tags = allRows(`SELECT t.* FROM tags t JOIN server_tags st ON t.id = st.tag_id WHERE st.server_id = ?`, [server.id]);
        server.tools = allRows(`SELECT * FROM tools WHERE server_id = ?`, [server.id]);
        server.resources = allRows(`SELECT * FROM resources WHERE server_id = ?`, [server.id]);
        server.prompts = allRows(`SELECT * FROM prompts WHERE server_id = ?`, [server.id]);
        server.versions = allRows(`SELECT * FROM server_versions WHERE server_id = ? ORDER BY created_at DESC`, [server.id]);
    }
    return server;
}

function createServer(data) {
    const id = uuidv4();
    const now = new Date().toISOString();

    runSql(`
        INSERT INTO servers (id, slug, name, author_id, description, long_description, github_url, npm_package, language, hosting, license, version, category_id, security_status, is_featured, is_official, source_json, listing_status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        id, data.slug, data.name, data.author_id, data.description, data.long_description || '',
        data.github_url || '', data.npm_package || '', data.language || 'other',
        data.hosting || 'local', data.license || 'MIT', data.version || '1.0.0',
        data.category_id, data.security_status || 'unverified', data.is_featured ? 1 : 0,
        data.is_official ? 1 : 0,
        data.source ? JSON.stringify(data.source) : null,
        data.listing_status || 'pending', now, now
    ]);

    // Add tools
    if (data.tools && Array.isArray(data.tools)) {
        for (const tool of data.tools) {
            const toolId = uuidv4();
            runSql(`INSERT INTO tools (id, server_id, name, description, input_schema, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
                [toolId, id, tool.name, tool.description || '', JSON.stringify(tool.input_schema || {}), now]);
        }
    }

    if (data.tags && Array.isArray(data.tags)) {
        for (const tag_id of data.tags) {
            runSql(`INSERT OR IGNORE INTO server_tags (server_id, tag_id) VALUES (?, ?)`, [id, tag_id]);
        }
    }

    // Add initial version
    const versionId = uuidv4();
    runSql(`INSERT INTO server_versions (id, server_id, version, changelog, created_at) VALUES (?, ?, ?, ?, ?)`,
        [versionId, id, data.version || '1.0.0', 'Initial release', now]);

    runSql(`UPDATE categories SET server_count = server_count + 1 WHERE id = ?`, [data.category_id]);
    return getServerBySlug(data.slug);
}

function updateServer(slug, data) {
    const server = oneRow(`SELECT id FROM servers WHERE slug = ?`, [slug]);
    if (!server) return null;

    const now = new Date().toISOString();
    const updates = [];
    const params = [];

    const allowedFields = ['name', 'description', 'long_description', 'github_url', 'npm_package', 'language', 'hosting', 'license', 'version', 'category_id', 'security_status', 'is_featured', 'is_official'];

    for (const field of allowedFields) {
        if (data[field] !== undefined) {
            updates.push(`${field} = ?`);
            params.push(data[field]);
        }
    }

    if (updates.length > 0) {
        updates.push(`updated_at = ?`);
        params.push(now);
        params.push(server.id);
        runSql(`UPDATE servers SET ${updates.join(', ')} WHERE id = ?`, params);
    }

    if (data.tags && Array.isArray(data.tags)) {
        runSql(`DELETE FROM server_tags WHERE server_id = ?`, [server.id]);
        for (const tag_id of data.tags) {
            runSql(`INSERT OR IGNORE INTO server_tags (server_id, tag_id) VALUES (?, ?)`, [server.id, tag_id]);
        }
    }

    return getServerBySlug(slug);
}

function deleteServer(slug) {
    const server = oneRow(`SELECT id, category_id FROM servers WHERE slug = ?`, [slug]);
    if (!server) return false;

    runSql(`DELETE FROM server_tags WHERE server_id = ?`, [server.id]);
    runSql(`DELETE FROM server_versions WHERE server_id = ?`, [server.id]);
    runSql(`DELETE FROM tools WHERE server_id = ?`, [server.id]);
    runSql(`DELETE FROM resources WHERE server_id = ?`, [server.id]);
    runSql(`DELETE FROM prompts WHERE server_id = ?`, [server.id]);
    runSql(`DELETE FROM installs WHERE server_id = ?`, [server.id]);
    runSql(`DELETE FROM servers WHERE id = ?`, [server.id]);
    runSql(`UPDATE categories SET server_count = MAX(0, server_count - 1) WHERE id = ?`, [server.category_id]);
    return true;
}

function getTools(serverId) {
    return allRows(`SELECT * FROM tools WHERE server_id = ?`, [serverId]);
}

function getCategories() {
    return allRows(`SELECT * FROM categories ORDER BY name ASC`);
}

function getCategoryBySlug(slug) {
    return oneRow(`SELECT * FROM categories WHERE slug = ?`, [slug]);
}

function getTags() {
    return allRows(`SELECT * FROM tags ORDER BY name ASC`);
}

function getClients() {
    return allRows(`SELECT * FROM clients ORDER BY name ASC`);
}

function searchServers(query) {
    return getServers({ q: query, limit: 50 });
}

function getUserByEmail(email) {
    return oneRow(`SELECT * FROM users WHERE email = ?`, [email]);
}

function getUserByUsername(username) {
    return oneRow(`SELECT * FROM users WHERE username = ?`, [username]);
}

function getUserServers(userId) {
    const servers = allRows(`
        SELECT s.*, c.name as category_name, c.slug as category_slug
        FROM servers s
        JOIN categories c ON s.category_id = c.id
        WHERE s.author_id = ?
        ORDER BY s.created_at DESC
    `, [userId]);

    for (let server of servers) {
        server.tags = allRows(`SELECT t.* FROM tags t JOIN server_tags st ON t.id = st.tag_id WHERE st.server_id = ?`, [server.id]);
    }
    return servers;
}

function createUser(data) {
    const id = uuidv4();
    const now = new Date().toISOString();
    runSql(`
        INSERT INTO users (id, username, email, password_hash, display_name, avatar_url, bio, website, github_username, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        id, data.username, data.email, data.password_hash, data.display_name || data.username,
        data.avatar_url || null, data.bio || null, data.website || null, data.github_username || null,
        now, now
    ]);
    return oneRow(`SELECT id, username, email, display_name, avatar_url, bio, website, github_username, created_at FROM users WHERE id = ?`, [id]);
}

function getStats() {
    const serverCount = oneRow(`SELECT COUNT(*) as count FROM servers s WHERE ${LISTED}`);
    const userCount = oneRow(`SELECT COUNT(*) as count FROM users`);
    const installCount = oneRow(`SELECT SUM(install_count) as count FROM servers`);
    const toolCount = oneRow(`SELECT COUNT(*) as count FROM tools`);
    const clientCount = oneRow(`SELECT COUNT(*) as count FROM clients`);
    return {
        servers: serverCount ? serverCount.count : 0,
        publishers: userCount ? userCount.count : 0,
        installs: installCount ? (installCount.count || 0) : 0,
        tools: toolCount ? toolCount.count : 0,
        clients: clientCount ? clientCount.count : 0
    };
}

function trackInstall(serverId, data) {
    const id = uuidv4();
    const now = new Date().toISOString();

    runSql(`INSERT INTO installs (id, server_id, user_id, client_type, created_at) VALUES (?, ?, ?, ?, ?)`,
        [id, serverId, data.user_id || null, data.client_type || 'unknown', now]);
    runSql(`UPDATE servers SET install_count = install_count + 1 WHERE id = ?`, [serverId]);

    return { success: true, install_id: id };
}

function getServerVersions(serverId) {
    return allRows(`SELECT * FROM server_versions WHERE server_id = ? ORDER BY created_at DESC`, [serverId]);
}

function getFeaturedServers(limit = 6) {
    const servers = allRows(`
        SELECT s.*, u.username as author_username, u.display_name as author_display_name, c.name as category_name, c.slug as category_slug
        FROM servers s
        JOIN users u ON s.author_id = u.id
        JOIN categories c ON s.category_id = c.id
        WHERE s.is_featured = 1 AND ${LISTED}
        ORDER BY s.stars DESC
        LIMIT ?
    `, [limit]);

    for (let server of servers) {
        server.tags = allRows(`SELECT t.* FROM tags t JOIN server_tags st ON t.id = st.tag_id WHERE st.server_id = ?`, [server.id]);
    }
    return servers;
}

function getPopularServers(limit = 8) {
    const servers = allRows(`
        SELECT s.*, u.username as author_username, u.display_name as author_display_name, c.name as category_name, c.slug as category_slug
        FROM servers s
        JOIN users u ON s.author_id = u.id
        JOIN categories c ON s.category_id = c.id
        WHERE ${LISTED}
        ORDER BY s.stars DESC
        LIMIT ?
    `, [limit]);

    for (let server of servers) {
        server.tags = allRows(`SELECT t.* FROM tags t JOIN server_tags st ON t.id = st.tag_id WHERE st.server_id = ?`, [server.id]);
    }
    return servers;
}

function getRecentServers(limit = 8) {
    const servers = allRows(`
        SELECT s.*, u.username as author_username, u.display_name as author_display_name, c.name as category_name, c.slug as category_slug
        FROM servers s
        JOIN users u ON s.author_id = u.id
        JOIN categories c ON s.category_id = c.id
        WHERE ${LISTED}
        ORDER BY s.created_at DESC
        LIMIT ?
    `, [limit]);

    for (let server of servers) {
        server.tags = allRows(`SELECT t.* FROM tags t JOIN server_tags st ON t.id = st.tag_id WHERE st.server_id = ?`, [server.id]);
    }
    return servers;
}

module.exports = {
    initDb,
    getDb,
    transaction,
    getServers,
    getServerBySlug,
    createServer,
    updateServer,
    deleteServer,
    getTools,
    getCategories,
    getCategoryBySlug,
    getTags,
    getClients,
    searchServers,
    getUserByEmail,
    getUserByUsername,
    getUserServers,
    createUser,
    getStats,
    trackInstall,
    getServerVersions,
    getFeaturedServers,
    getPopularServers,
    getRecentServers,
    allRows,
    oneRow,
    runSql
};
