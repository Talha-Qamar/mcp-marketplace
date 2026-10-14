const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.MCS_DB_PATH || path.join(__dirname, 'marketplace.db');
const schemaPath = path.join(__dirname, 'schema.sql');

async function seed() {

    // Remove existing DB to start fresh
    for (const f of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
        if (fs.existsSync(f)) fs.unlinkSync(f);
    }
    if (!fs.existsSync(dbPath)) console.log('Removed old database (if any).');

    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    const bindable = p => (p || []).map(v => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v));
    const run = (sql, params) => db.prepare(sql).run(bindable(params));
    db.exec('BEGIN');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    db.exec(schema);

    const now = new Date().toISOString();

    console.log('Seeding Database...\n');

    // --- 1. Create Users ---
    const users = [];
    const salt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync('password123', salt);

    const userData = [
        { username: 'anthropic_official', display: 'Anthropic', bio: 'Official MCP server publisher', github: 'anthropics' },
        { username: 'alice_dev', display: 'Alice Chen', bio: 'Full-stack developer and MCP enthusiast', github: 'alicedev' },
        { username: 'bob_builder', display: 'Bob Martinez', bio: 'Open-source contributor', github: 'bobbuilder' },
        { username: 'charlie_ai', display: 'Charlie Kim', bio: 'AI researcher and tool builder', github: 'charlieai' },
        { username: 'dave_sec', display: 'Dave Wilson', bio: 'Security researcher', github: 'davesec' },
    ];

    for (const u of userData) {
        const id = uuidv4();
        users.push({ id, username: u.username });
        run(`INSERT INTO users (id, username, email, password_hash, display_name, bio, github_username, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, u.username, `${u.username}@example.com`, passwordHash, u.display, u.bio, u.github, now, now]);
    }
    console.log(`✓ Created ${users.length} users`);

    // --- 2. Create Categories ---
    const categoriesData = [
        { slug: 'developer-tools', name: 'Developer Tools', description: 'Code editors, linters, formatters, and development utilities', icon: 'hammer' },
        { slug: 'ai-agents', name: 'AI & Agents', description: 'Agentic workflows, model orchestration, and AI assistants', icon: 'sparkles' },
        { slug: 'cloud-infrastructure', name: 'Cloud & Infrastructure', description: 'AWS, GCP, Azure, Docker, Kubernetes integrations', icon: 'cloud' },
        { slug: 'search', name: 'Search', description: 'Web search, document search, and information retrieval', icon: 'search' },
        { slug: 'databases', name: 'Databases', description: 'PostgreSQL, MySQL, SQLite, MongoDB, Redis connections', icon: 'database' },
        { slug: 'memory-knowledge', name: 'Memory & Knowledge', description: 'Persistent memory, note-taking, and knowledge graphs', icon: 'brain' },
        { slug: 'media-design', name: 'Media & Design', description: 'Image generation, video processing, and design tools', icon: 'image' },
        { slug: 'app-automation', name: 'App Automation', description: 'Slack, GitHub, Jira, Notion, and workflow automation', icon: 'zap' },
        { slug: 'security', name: 'Security', description: 'Vulnerability scanners, auth tools, and security analysis', icon: 'shield' },
        { slug: 'communication', name: 'Communication', description: 'Email, messaging, notifications, and chat integrations', icon: 'message-circle' }
    ];

    const categoryMap = {};
    for (const c of categoriesData) {
        const id = uuidv4();
        categoryMap[c.slug] = id;
        run(`INSERT INTO categories (id, slug, name, description, icon, server_count) VALUES (?, ?, ?, ?, ?, ?)`,
            [id, c.slug, c.name, c.description, c.icon, 0]);
    }
    console.log(`✓ Created ${categoriesData.length} categories`);

    // --- 3. Create Tags ---
    const tagsData = [
        'python', 'typescript', 'javascript', 'go', 'rust', 'github', 'browser', 'search',
        'database', 'memory', 'cloud', 'api', 'ai', 'filesystem', 'docker', 'kubernetes',
        'slack', 'automation', 'monitoring', 'testing', 'devtools', 'llm', 'security',
        'web-scraping', 'email', 'notifications'
    ];

    const tagMap = {};
    for (const t of tagsData) {
        const id = uuidv4();
        tagMap[t] = id;
        run(`INSERT INTO tags (id, slug, name) VALUES (?, ?, ?)`, [id, t, t.replace(/-/g, ' ')]);
    }
    console.log(`✓ Created ${tagsData.length} tags`);

    // --- 4. Create Clients ---
    const clientsData = [
        { slug: 'claude-desktop', name: 'Claude Desktop', description: 'Official Anthropic desktop client with native MCP support. Connect to local and remote MCP servers through the app settings.', type: 'Desktop App', mcp_support: 'Full', website: 'https://claude.ai/download' },
        { slug: 'cursor', name: 'Cursor', description: 'AI-first code editor with built-in MCP integration. Add MCP servers in Settings > Features > MCP.', type: 'Code Editor', mcp_support: 'Full', website: 'https://cursor.com' },
        { slug: 'vscode-copilot', name: 'VS Code (Copilot)', description: 'Visual Studio Code with GitHub Copilot extension supports MCP servers for enhanced agent capabilities.', type: 'Code Editor', mcp_support: 'Full', website: 'https://code.visualstudio.com' },
        { slug: 'windsurf', name: 'Windsurf', description: 'AI-native IDE by Codeium with deep MCP protocol support for tool-augmented coding.', type: 'Code Editor', mcp_support: 'Full', website: 'https://windsurf.com' },
        { slug: 'cline', name: 'Cline', description: 'Autonomous coding agent for VS Code that can connect to MCP servers for extended tool access.', type: 'VS Code Extension', mcp_support: 'Full', website: 'https://cline.bot' },
        { slug: 'opensumi', name: 'OpenSumi', description: 'Open-source IDE framework with MCP integration support for building custom AI-powered editors.', type: 'IDE Framework', mcp_support: 'Partial', website: 'https://opensumi.com' },
        { slug: 'zed', name: 'Zed', description: 'High-performance, multiplayer code editor with emerging MCP support for AI assistant extensions.', type: 'Code Editor', mcp_support: 'Partial', website: 'https://zed.dev' },
        { slug: 'continue-dev', name: 'Continue', description: 'Open-source AI code assistant that works in VS Code and JetBrains with MCP server connections.', type: 'IDE Extension', mcp_support: 'Full', website: 'https://continue.dev' }
    ];

    for (const cl of clientsData) {
        run(`INSERT INTO clients (id, slug, name, description, website, type, mcp_support, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [uuidv4(), cl.slug, cl.name, cl.description, cl.website, cl.type, cl.mcp_support, now]);
    }
    console.log(`✓ Created ${clientsData.length} clients`);

    // --- 5. Create Servers from JSON ---
    const serversToCreate = [];
    const dataDir = path.join(__dirname, 'data');
    if (fs.existsSync(dataDir)) {
        const files = fs.readdirSync(dataDir).filter(f => f.endsWith('.json'));
        for (const file of files) {
            const content = fs.readFileSync(path.join(dataDir, file), 'utf8');
            try {
                const categoryServers = JSON.parse(content);
                serversToCreate.push(...categoryServers);
            } catch (err) {
                console.error(`Error parsing ${file}:`, err);
            }
        }
    }

    let serverCount = 0;
    for (const s of serversToCreate) {
        const serverId = uuidv4();
        
        let authorId = users[0].id;
        if (s.author_username) {
            const authorObj = users.find(u => u.username === s.author_username);
            if (authorObj) authorId = authorObj.id;
        } else if (s.author !== undefined) {
            authorId = users[s.author].id;
        }
        
        const catId = categoryMap[s.category_slug || s.category] || categoryMap['developer-tools'];

        const hosting = s.hosting || 'local';
        const license = s.license || 'MIT';
        const version = s.version || '1.0.0';
        const longDesc = s.long_description || `# ${s.name}\n\n${s.description}\n\n## Installation\n\nAdd this server to your MCP client configuration.\n\n## Usage\n\nConnect and start using the available tools.`;
        const transport = s.transport || (s.hosting === 'remote' ? 'Streamable HTTP' : 'stdio');
        const auth = s.authentication || 'None';

        run(`
            INSERT INTO servers (id, slug, name, author_id, description, long_description, github_url, npm_package, language, hosting, transport, authentication, license, version, stars, forks, install_count, category_id, security_status, is_featured, is_official, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            serverId, s.slug, s.name, authorId, s.description, longDesc,
            s.github_url || '', s.npm_package || '', s.language || 'typescript',
            hosting, transport, auth, license, version,
            s.stars || 0, s.forks || 0, s.install_count || s.installs || 0,
            catId, s.security_status || s.security || 'unverified',
            s.is_featured !== undefined ? s.is_featured : (s.featured || 0), 
            s.is_official !== undefined ? s.is_official : (s.official || 0), 
            now, now
        ]);

        // Update category count
        run(`UPDATE categories SET server_count = server_count + 1 WHERE id = ?`, [catId]);

        // Add tags
        const addedTags = new Set();
        if (s.tags) {
            for (const t of s.tags) {
                if (!addedTags.has(t) && tagMap[t]) {
                    run(`INSERT OR IGNORE INTO server_tags (server_id, tag_id) VALUES (?, ?)`, [serverId, tagMap[t]]);
                    addedTags.add(t);
                }
            }
        }

        // Add tools
        if (s.tools) {
            for (const tool of s.tools) {
                const toolSchema = tool.input_schema ? (typeof tool.input_schema === 'string' ? tool.input_schema : JSON.stringify(tool.input_schema)) : JSON.stringify(tool.schema || {});
                run(`INSERT INTO tools (id, server_id, name, description, input_schema, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
                    [uuidv4(), serverId, tool.name, tool.description || tool.desc || '', toolSchema, now]);
            }
        }

        // Add resources
        if (s.resources) {
            for (const r of s.resources) {
                run(`INSERT INTO resources (id, server_id, name, description, uri_template, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
                    [uuidv4(), serverId, r.name, r.description || r.desc || '', r.uri_template || r.uri || '', now]);
            }
        }

        // Add version
        run(`INSERT INTO server_versions (id, server_id, version, changelog, created_at) VALUES (?, ?, ?, ?, ?)`,
            [uuidv4(), serverId, '1.0.0', 'Initial release', now]);

        // Add a second version for some servers
        if (s.stars > 500) {
            run(`INSERT INTO server_versions (id, server_id, version, changelog, created_at) VALUES (?, ?, ?, ?, ?)`,
                [uuidv4(), serverId, '1.1.0', 'Bug fixes and performance improvements', now]);
        }

        serverCount++;
    }

    console.log(`✓ Created ${serverCount} servers with tools, tags, and versions`);

    db.exec('COMMIT');
    // Seeded security persona reviews flagged submissions (role column, spec §9.1).
    db.prepare(`UPDATE users SET role = 'admin' WHERE username = 'dave_sec'`).run();
    db.close();

    console.log(`\n✅ Database seeded successfully at ${dbPath}`);
    console.log(`   Total: ${serverCount} servers, ${users.length} users, ${categoriesData.length} categories, ${tagsData.length} tags, ${clientsData.length} clients`);
}

seed().catch(err => {
    console.error('Seeding failed:', err);
    process.exit(1);
});
