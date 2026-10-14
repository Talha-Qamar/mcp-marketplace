/* =============================================================
   MCP Marketplace — Application Logic
   ============================================================= */

/* ---- High-Quality Mock Data ---- */
const MOCK_USER = {
  username:    'mtariq_dev',
  displayName: 'Muhammad Tariq',
  email:       'mtariq@example.com',
  bio:         'Full-stack engineer & AI tooling enthusiast. Building the future of MCP integrations. Contributor to open-source AI infrastructure.',
  github:      'mtariq-dev',
  stars:       847,
  publishedServers: 6,
  totalInstalls: '12.4k',
};

const MOCK_SERVERS = [
  {
    slug: 'github',
    name: 'GitHub MCP Server',
    description: 'Full GitHub API integration — manage repos, issues, PRs, and code search directly from your AI agent.',
    long_description: `## GitHub MCP Server\n\nThis official server integrates the complete GitHub REST & GraphQL API into any MCP-compatible AI client.\n\n### Features\n- Create, read, update, and delete repositories\n- Manage issues, pull requests, and code reviews\n- Full semantic code search across public and private repos\n- Webhook management and GitHub Actions integration\n- File operations with branch support\n\n### Authentication\nRequires a GitHub Personal Access Token with appropriate scopes.`,
    author: 'modelcontextprotocol',
    author_username: 'modelcontextprotocol',
    author_display_name: 'Model Context Protocol',
    language: 'TypeScript',
    hosting: 'Local',
    transport: 'stdio',
    stars: 4200,
    install_count: 187400,
    npm_package: '@modelcontextprotocol/server-github',
    github_url: 'https://github.com/modelcontextprotocol/servers',
    tags: ['git', 'code', 'devtools', 'github'],
    category_name: 'Developer Tools',
    category_slug: 'developer-tools',
    version: 'v1.0.0',
    license: 'MIT',
    security_status: 'verified',
    verified: true,
  },
  {
    slug: 'postgresql',
    name: 'PostgreSQL MCP Server',
    description: 'Connect AI agents directly to your PostgreSQL database for read and write operations with schema introspection.',
    long_description: `## PostgreSQL MCP Server\n\nProvides a full MCP interface to PostgreSQL databases, enabling AI agents to query, analyze, and manage data.\n\n### Features\n- Execute arbitrary SQL queries (with permission controls)\n- Schema introspection and table discovery\n- Data export in multiple formats\n- Connection pooling support\n- Read-only and read-write operation modes`,
    author: 'modelcontextprotocol',
    author_display_name: 'Model Context Protocol',
    language: 'TypeScript',
    hosting: 'Local',
    transport: 'stdio',
    stars: 2890,
    install_count: 94300,
    npm_package: '@modelcontextprotocol/server-postgres',
    github_url: 'https://github.com/modelcontextprotocol/servers',
    tags: ['database', 'sql', 'postgresql', 'data'],
    category_name: 'Database',
    category_slug: 'database',
    version: 'v0.6.2',
    license: 'MIT',
    security_status: 'verified',
    verified: true,
  },
  {
    slug: 'puppeteer',
    name: 'Puppeteer MCP Server',
    description: 'Browser automation and web scraping for AI agents. Navigate pages, fill forms, take screenshots, and extract structured data.',
    long_description: `## Puppeteer MCP Server\n\nExposes Puppeteer browser automation as MCP tools, enabling AI agents to interact with web browsers.\n\n### Features\n- Navigate to URLs and interact with page elements\n- Take full-page or element-specific screenshots\n- Fill out and submit forms\n- Extract structured data from any webpage\n- Execute JavaScript in page context\n- PDF generation from web content`,
    author: 'modelcontextprotocol',
    author_display_name: 'Model Context Protocol',
    language: 'TypeScript',
    hosting: 'Local',
    transport: 'stdio',
    stars: 3100,
    install_count: 78200,
    npm_package: '@modelcontextprotocol/server-puppeteer',
    github_url: 'https://github.com/modelcontextprotocol/servers',
    tags: ['browser', 'automation', 'scraping', 'web'],
    category_name: 'Browser Automation',
    category_slug: 'browser',
    version: 'v0.3.1',
    license: 'MIT',
    security_status: 'verified',
    verified: true,
  },
  {
    slug: 'brave-search',
    name: 'Brave Search MCP',
    description: 'Privacy-first web and local search powered by the Brave Search API. Supports web results, news, and AI summaries.',
    long_description: `## Brave Search MCP Server\n\nIntegrates Brave Search's privacy-first search engine into MCP clients.\n\n### Features\n- Web search with rich result snippets\n- News search with publication dates\n- Local business and location search\n- AI-generated answer summaries\n- Safesearch controls\n- Results pagination`,
    author: 'modelcontextprotocol',
    author_display_name: 'Model Context Protocol',
    language: 'TypeScript',
    hosting: 'Local',
    transport: 'stdio',
    stars: 1740,
    install_count: 45100,
    npm_package: '@modelcontextprotocol/server-brave-search',
    github_url: 'https://github.com/modelcontextprotocol/servers',
    tags: ['search', 'web', 'privacy', 'brave'],
    category_name: 'Search',
    category_slug: 'search',
    version: 'v0.4.0',
    license: 'MIT',
    security_status: 'verified',
    verified: true,
  },
  {
    slug: 'filesystem',
    name: 'Filesystem MCP Server',
    description: 'Secure local filesystem access — read, write, list, and search files within configurable allowed directories.',
    long_description: `## Filesystem MCP Server\n\nProvides controlled filesystem access to AI agents within explicitly allowed directory paths.\n\n### Features\n- Read files (text and binary)\n- Write and append to files\n- List directory contents with metadata\n- Search files by name patterns (glob)\n- Move, copy, and delete files\n- Create directories`,
    author: 'modelcontextprotocol',
    author_display_name: 'Model Context Protocol',
    language: 'TypeScript',
    hosting: 'Local',
    transport: 'stdio',
    stars: 3800,
    install_count: 213000,
    npm_package: '@modelcontextprotocol/server-filesystem',
    github_url: 'https://github.com/modelcontextprotocol/servers',
    tags: ['filesystem', 'files', 'local', 'io'],
    category_name: 'Filesystem',
    category_slug: 'filesystem',
    version: 'v1.1.0',
    license: 'MIT',
    security_status: 'verified',
    verified: true,
  },
  {
    slug: 'slack',
    name: 'Slack MCP Server',
    description: 'Read and send Slack messages, manage channels, search message history, and interact with Slack workspace data.',
    long_description: `## Slack MCP Server\n\nFull Slack API integration for AI agents via MCP.\n\n### Features\n- Post messages to channels and DMs\n- Read channel history and thread replies\n- Search across workspace messages\n- List channels, users, and workspaces\n- React to messages with emoji\n- File uploads and attachments`,
    author: 'modelcontextprotocol',
    author_display_name: 'Model Context Protocol',
    language: 'TypeScript',
    hosting: 'Local',
    transport: 'stdio',
    stars: 1350,
    install_count: 31800,
    npm_package: '@modelcontextprotocol/server-slack',
    github_url: 'https://github.com/modelcontextprotocol/servers',
    tags: ['slack', 'messaging', 'communication', 'workspace'],
    category_name: 'Communication',
    category_slug: 'communication',
    version: 'v0.5.0',
    license: 'MIT',
    security_status: 'verified',
    verified: true,
  },
];

const MOCK_CATEGORIES = [
  { slug: 'developer-tools', name: 'Developer Tools',    icon: 'code',           server_count: 48 },
  { slug: 'database',        name: 'Database',           icon: 'database',       server_count: 31 },
  { slug: 'search',          name: 'Search & Web',       icon: 'search',         server_count: 24 },
  { slug: 'communication',   name: 'Communication',      icon: 'message-circle', server_count: 19 },
  { slug: 'ai-tools',        name: 'AI & Automation',    icon: 'sparkles',       server_count: 37 },
  { slug: 'cloud',           name: 'Cloud Services',     icon: 'cloud',          server_count: 22 },
  { slug: 'filesystem',      name: 'Filesystem & IO',    icon: 'file-text',      server_count: 15 },
  { slug: 'security',        name: 'Security',           icon: 'shield',         server_count: 11 },
  { slug: 'browser',         name: 'Browser Automation', icon: 'globe',          server_count: 14 },
  { slug: 'monitoring',      name: 'Monitoring',         icon: 'activity',       server_count: 9  },
];

const MOCK_CLIENTS = [
  {
    name: 'Claude Desktop',
    type: 'ai-client',
    description: 'Anthropic\'s official AI assistant with full MCP support. Connect any MCP server for local data access, tool execution, and real-time context.',
    website: 'https://claude.ai/download',
    features: ['stdio', 'HTTP', 'SSE', 'OAuth'],
    server_count: '1,200+',
  },
  {
    name: 'Cursor',
    type: 'editor',
    description: 'The AI-first code editor built on VS Code. Add MCP servers to give Cursor access to your entire development ecosystem.',
    website: 'https://cursor.sh',
    features: ['stdio', 'HTTP', 'Project Scope'],
    server_count: '800+',
  },
  {
    name: 'VS Code + Cline',
    type: 'editor',
    description: 'The world\'s most popular code editor with Cline extension for autonomous AI coding. Full MCP server support for tool access.',
    website: 'https://github.com/cline/cline',
    features: ['stdio', 'SSE', 'Browser'],
    server_count: '900+',
  },
  {
    name: 'GitHub Copilot',
    type: 'ai-client',
    description: 'GitHub\'s AI pair programmer now supports MCP for repository and external tool integration, available in editors across the ecosystem.',
    website: 'https://github.com/features/copilot',
    features: ['HTTP', 'SSE', 'OAuth 2.0'],
    server_count: '500+',
  },
];

const MOCK_TOOLS_BY_SERVER = {
  'github': [
    {
      id: 'gh-1',
      name: 'create_or_update_file',
      description: 'Creates a new file or updates an existing file in a GitHub repository. Supports creating files with initial content or updating existing file contents via the GitHub Contents API.',
      input_schema: JSON.stringify({
        type: 'object',
        properties: {
          owner:   { type: 'string', description: 'Repository owner (username or org)' },
          repo:    { type: 'string', description: 'Repository name' },
          path:    { type: 'string', description: 'File path within the repository' },
          content: { type: 'string', description: 'File content (base64 encoded)' },
          message: { type: 'string', description: 'Commit message' },
          branch:  { type: 'string', description: 'Branch name (defaults to repo default)' },
          sha:     { type: 'string', description: 'SHA of file being replaced (required for updates)' },
        },
        required: ['owner', 'repo', 'path', 'content', 'message'],
      }),
    },
    {
      id: 'gh-2',
      name: 'search_code',
      description: 'Searches for code across GitHub repositories using GitHub\'s code search API. Supports qualifiers like language, repo, org, and path filters.',
      input_schema: JSON.stringify({
        type: 'object',
        properties: {
          q:        { type: 'string', description: 'Search query with GitHub code search syntax' },
          per_page: { type: 'number', description: 'Results per page (max 100)' },
          page:     { type: 'number', description: 'Page number for pagination' },
        },
        required: ['q'],
      }),
    },
    {
      id: 'gh-3',
      name: 'create_issue',
      description: 'Creates a new issue in a GitHub repository with support for labels, assignees, and milestone assignment.',
      input_schema: JSON.stringify({
        type: 'object',
        properties: {
          owner:     { type: 'string', description: 'Repository owner' },
          repo:      { type: 'string', description: 'Repository name' },
          title:     { type: 'string', description: 'Issue title' },
          body:      { type: 'string', description: 'Issue body content (Markdown supported)' },
          labels:    { type: 'array', items: { type: 'string' }, description: 'Labels to apply' },
          assignees: { type: 'array', items: { type: 'string' }, description: 'Usernames to assign' },
        },
        required: ['owner', 'repo', 'title'],
      }),
    },
  ],
  'postgresql': [
    {
      id: 'pg-1',
      name: 'query',
      description: 'Executes a SQL query against the connected PostgreSQL database and returns results as structured data. Supports parameterized queries for safety.',
      input_schema: JSON.stringify({
        type: 'object',
        properties: {
          sql:    { type: 'string', description: 'SQL query to execute' },
          params: { type: 'array', items: { type: 'string' }, description: 'Query parameters for parameterized queries' },
        },
        required: ['sql'],
      }),
    },
    {
      id: 'pg-2',
      name: 'list_tables',
      description: 'Lists all tables in the connected database with their column schemas, data types, constraints, and row counts.',
      input_schema: JSON.stringify({
        type: 'object',
        properties: {
          schema: { type: 'string', description: 'Schema name (defaults to public)', default: 'public' },
        },
      }),
    },
  ],
  'brave-search': [
    {
      id: 'bs-1',
      name: 'brave_web_search',
      description: 'Performs a web search using the Brave Search API and returns rich result snippets including titles, URLs, descriptions, and news articles.',
      input_schema: JSON.stringify({
        type: 'object',
        properties: {
          query:       { type: 'string', description: 'Search query string' },
          count:       { type: 'number', description: 'Number of results to return (1-20, default 10)' },
          search_lang: { type: 'string', description: 'Language code for results (e.g. "en", "de")' },
          country:     { type: 'string', description: 'Country code for local results (e.g. "US", "GB")' },
          freshness:   { type: 'string', description: 'Filter by date: "pd" (past day), "pw" (past week), "pm" (past month)' },
        },
        required: ['query'],
      }),
    },
  ],
};

const MOCK_STATS = {
  totalServers:   142,
  totalPublishers: 89,
  totalInstalls:  '1.2M',
  totalClients:   15,
};

/* =============================================================
   APPLICATION
   ============================================================= */
const App = {
  currentUser: null,
  _serverCache: {},

  async init() {
    this.initTheme();

    try {
      this.currentUser = await API.getCurrentUser();
    } catch (_) {
      this.currentUser = null;
    }

    this.renderNavbar();
    this.renderFooter();

    // Bind nav search
    setTimeout(() => {
      const ns = document.getElementById('nav-search');
      if (ns) {
        ns.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' && ns.value.trim()) {
            window.location.href = `/servers.html?q=${encodeURIComponent(ns.value.trim())}`;
          }
        });
        // ⌘K shortcut
        document.addEventListener('keydown', (e) => {
          if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            ns.focus();
            ns.select();
          }
        });
      }
    }, 100);

    // The server serves every page at both /name and /name.html, so match on
    // the page name, not the .html suffix (clean URLs left forms unwired).
    const page = (window.location.pathname.replace(/\/+$/, '').split('/').pop() || 'index').replace(/\.html$/, '');
    if (page === 'index')                                    this.initHomePage();
    else if (page === 'servers')                             this.initServersPage();
    else if (page === 'server-detail')                       this.initServerDetailPage();
    else if (page === 'publish')  {
      if (!this.currentUser) { window.location.href = '/login.html'; return; }
      this.initPublishPage();
    }
    else if (page === 'clients')                             this.initClientsPage();
    else if (page === 'categories')                          this.initCategoriesPage();
    else if (page === 'login')                               this.initLoginPage();
    else if (page === 'register')                            this.initRegisterPage();
    else if (page === 'profile') {
      if (!this.currentUser) { window.location.href = '/login.html'; return; }
      this.initProfilePage();
    }
  },

  /* ---- Theme Management ---- */
  initTheme() {
    const saved = localStorage.getItem('mcp_theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    document.documentElement.setAttribute('data-theme', saved);
    this.updateThemeToggleIcon(saved);
  },

  toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = current === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('mcp_theme', next); } catch (_) {}
    this.updateThemeToggleIcon(next);
  },

  updateThemeToggleIcon(theme) {
    const iconSpan = document.getElementById('theme-toggle-icon');
    const btn = document.getElementById('theme-toggle-btn');
    if (!iconSpan) return;
    if (theme === 'light') {
      iconSpan.innerHTML = typeof icon === 'function' ? icon('moon', 16) : '🌙';
      if (btn) btn.setAttribute('title', 'Switch to Dark Mode');
    } else {
      iconSpan.innerHTML = typeof icon === 'function' ? icon('sun', 16) : '☀️';
      if (btn) btn.setAttribute('title', 'Switch to Light Mode');
    }
  },

  renderNavbar() {
    const c = document.getElementById('navbar-container');
    // Use mock user if not logged in for demo
    const displayUser = this.currentUser || null;
    if (c) c.innerHTML = Components.createNavbar(displayUser);
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    this.updateThemeToggleIcon(currentTheme);
  },

  renderFooter() {
    const c = document.getElementById('footer-container');
    if (c) c.innerHTML = Components.createFooter();
  },

  showToast(message, type = 'success') {
    let container = document.querySelector('.toast-container');
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    const toastIcons = {
      success: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
      error:   `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/></svg>`,
    };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `${toastIcons[type] || toastIcons.success} <span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 3000);
  },

  async logout() {
    try { await API.logout(); } catch (_) {}
    window.location.href = '/index.html';
  },

  /* ---- Home Page ---- */
  async initHomePage() {
    const statsEl   = document.getElementById('home-stats');
    const featEl    = document.getElementById('home-featured');
    const catsEl    = document.getElementById('home-categories');
    const faqEl     = document.getElementById('home-faq');

    // Skeletons
    if (statsEl)  statsEl.innerHTML  = Array(4).fill(Components.createSkeletonCard(100)).join('');
    if (featEl)   featEl.innerHTML   = Array(3).fill(Components.createSkeletonCard(240)).join('');

    try {
      const [stats, serversResp, categories] = await Promise.all([
        API.getStats().catch(() => MOCK_STATS),
        API.getServers({ limit: 6, sort: 'stars' }).catch(() => ({ data: MOCK_SERVERS })),
        API.getCategories().catch(() => MOCK_CATEGORIES),
      ]);

      const st = (typeof stats === 'object' && stats !== null) ? stats : MOCK_STATS;

      if (statsEl) {
        statsEl.className = 'stats-grid';
        statsEl.innerHTML = [
          Components.createStatCard('Total Servers',      (st.totalServers  || MOCK_STATS.totalServers).toLocaleString()),
          Components.createStatCard('Publishers',         (st.totalPublishers|| MOCK_STATS.totalPublishers).toLocaleString()),
          Components.createStatCard('Total Installs',     st.totalInstalls  || MOCK_STATS.totalInstalls),
          Components.createStatCard('Client Integrations',st.totalClients   || MOCK_STATS.totalClients),
        ].join('');
      }

      if (featEl) {
        const servers = serversResp?.data || serversResp || MOCK_SERVERS;
        const displayServers = (Array.isArray(servers) && servers.length) ? servers : MOCK_SERVERS;
        featEl.innerHTML = displayServers.slice(0, 6).map(s => Components.createServerCard(s)).join('');
      }

      if (catsEl) {
        const cats = (Array.isArray(categories) && categories.length) ? categories : MOCK_CATEGORIES;
        catsEl.innerHTML = cats.slice(0, 8).map(c => Components.createCategoryCard(c)).join('');
      }

      if (faqEl) {
        faqEl.innerHTML = [
          Components.createFaqItem(
            'What is MCP?',
            'Model Context Protocol (MCP) is an open standard by Anthropic that enables AI models to securely connect to external data sources, APIs, and tools. Think of it as a universal plugin system for AI agents.'
          ),
          Components.createFaqItem(
            'How do I install a server?',
            'Most TypeScript/JavaScript servers can be installed with <code>npx -y @modelcontextprotocol/server-name</code>. Python servers use <code>uvx mcp-server-name</code>. Check the Install tab on any server page for the exact configuration for your client.'
          ),
          Components.createFaqItem(
            'Can I publish my own server?',
            'Absolutely! Create an account, build your server following the MCP specification, then use our Publish form to list it in the marketplace. Verification is available for well-maintained, open-source servers.'
          ),
          Components.createFaqItem(
            'Which AI clients support MCP?',
            'Claude Desktop, Cursor, VS Code with Cline, GitHub Copilot, Zed, and many more. See our Clients page for the full list with setup instructions for each.'
          ),
        ].join('');
      }
    } catch (err) {
      console.error('Home page error:', err);
    }
  },

  /* ---- Servers Page ---- */
  async initServersPage() {
    this.currentServersPage = 1;
    this.currentServersFilters = {};

    const urlParams = new URLSearchParams(window.location.search);
    const q        = urlParams.get('q');
    const category = urlParams.get('category');

    const searchEl = document.getElementById('server-search-input');
    if (q && searchEl) { searchEl.value = q; this.currentServersFilters.q = q; }
    if (category)      this.currentServersFilters.category = [category];

    searchEl?.addEventListener('input', (e) => {
      this.currentServersFilters.q = e.target.value;
      this.currentServersPage = 1;
      clearTimeout(this._searchDebounce);
      this._searchDebounce = setTimeout(() => this.loadServers(), 300);
    });

    document.getElementById('sort-select')?.addEventListener('change', (e) => {
      this.currentServersFilters.sort = e.target.value;
      this.currentServersPage = 1;
      this.loadServers();
    });

    try {
      const categories = await API.getCategories().catch(() => MOCK_CATEGORIES);
      const sidebar = document.getElementById('sidebar-container');
      if (sidebar) {
        sidebar.innerHTML = Components.createFilterSidebar(
          Array.isArray(categories) ? categories : MOCK_CATEGORIES,
          this.currentServersFilters
        );
        sidebar.querySelectorAll('input[type="checkbox"]').forEach(cb => {
          cb.addEventListener('change', (e) => {
            const name = e.target.name, val = e.target.value;
            if (!this.currentServersFilters[name]) this.currentServersFilters[name] = [];
            if (e.target.checked) { if (!this.currentServersFilters[name].includes(val)) this.currentServersFilters[name].push(val); }
            else this.currentServersFilters[name] = this.currentServersFilters[name].filter(v => v !== val);
            this.currentServersPage = 1;
            this.loadServers();
          });
        });
      }
    } catch (e) { console.error(e); }

    this.loadServers();
  },

  async loadServers() {
    const grid      = document.getElementById('servers-grid');
    const paginator = document.getElementById('pagination-container');
    if (!grid) return;

    grid.innerHTML = Array(6).fill(Components.createSkeletonCard(220)).join('');

    try {
      const params = { ...this.currentServersFilters, page: this.currentServersPage, limit: 12 };
      const flat   = {};
      for (const [k, v] of Object.entries(params)) flat[k] = Array.isArray(v) ? v.join(',') : v;

      const response    = await API.getServers(flat);
      const servers     = response?.servers || response?.data || (Array.isArray(response) ? response : []);
      const totalPages  = response?.totalPages || 1;

      if (servers.length) {
        grid.innerHTML = servers.map(s => Components.createServerCard(s)).join('');
      } else {
        // Fallback to filtered mock data
        const q    = (this.currentServersFilters.q || '').toLowerCase();
        const mock = q
          ? MOCK_SERVERS.filter(s => s.name.toLowerCase().includes(q) || s.description.toLowerCase().includes(q))
          : MOCK_SERVERS;
        grid.innerHTML = mock.length
          ? mock.map(s => Components.createServerCard(s)).join('')
          : Components.createEmptyState(
              'No servers found',
              'Try adjusting your search or filters, or be the first to publish one!',
              { href: '/publish.html', label: 'Publish Your First Server' }
            );
      }

      if (paginator) paginator.innerHTML = Components.createPagination(this.currentServersPage, totalPages);
    } catch (err) {
      // Show mock data on API error
      grid.innerHTML = MOCK_SERVERS.map(s => Components.createServerCard(s)).join('');
    }
  },

  changePage(page) {
    this.currentServersPage = page;
    this.loadServers();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  },

  /* ---- Server Detail Page ---- */
  async initServerDetailPage() {
    const urlParams = new URLSearchParams(window.location.search);
    const slug = urlParams.get('slug');
    if (!slug) { window.location.href = '/servers.html'; return; }

    try {
      let server;
      try {
        server = await API.getServer(slug);
      } catch (_) {
        server = MOCK_SERVERS.find(s => s.slug === slug) || MOCK_SERVERS[0];
      }

      document.title = `${server.name} — MCP Marketplace`;

      const breadcrumb = document.getElementById('server-breadcrumb');
      if (breadcrumb) breadcrumb.textContent = server.name;

      const authorName   = server.author_display_name || server.author_username || server.author || 'Publisher';
      const tagsList     = (server.tags || []).map(t => typeof t === 'object' ? (t.name || t.slug) : t);
      const stars        = (server.stars || 0).toLocaleString();
      const installs     = (server.install_count || server.installs || 0).toLocaleString();
      const avatarEl     = brandAvatar(slug, server.name, 'avatar-lg');

      const headerEl = document.getElementById('server-header');
      if (headerEl) {
        headerEl.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1.5rem;border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:1.5rem;">
            <div style="display:flex;gap:1.25rem;align-items:center;">
              ${avatarEl}
              <div>
                <h1 style="margin-bottom:0.35rem;display:flex;align-items:center;gap:0.875rem;flex-wrap:wrap;font-size:1.875rem;">
                  ${server.name}
                  <span class="badge badge-success" style="font-size:0.8rem;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    Verified Publisher
                  </span>
                </h1>
                <p style="margin:0;color:var(--text-2);font-size:0.9375rem;">
                  Published by <strong style="color:var(--text-1);">${authorName}</strong>
                </p>
              </div>
            </div>
            <div style="display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center;">
              <button class="btn btn-outline" style="border-color:var(--accent-cyan);color:var(--accent-cyan);"
                onclick="navigator.clipboard.writeText('npx -y ${server.npm_package || '@modelcontextprotocol/server-' + slug}');App.showToast('CLI command copied!','success');return false;">
                <svg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><rect width='14' height='14' x='8' y='8' rx='2' ry='2'/><path d='M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2'/></svg>
                Copy Install
              </button>
              <a href="${server.github_url || '#'}" target="_blank" class="btn btn-outline">
                Repository
                <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" x2="21" y1="14" y2="3"/></svg>
              </a>
              <button class="btn btn-primary" onclick="App.trackInstall('${slug}')">
                ⚡ Install & Attach
              </button>
            </div>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:0.5rem;align-items:center;">
            <span class="client-chip" style="font-size:0.85rem;padding:0.35rem 0.85rem;">✓ Claude Desktop</span>
            <span class="client-chip" style="font-size:0.85rem;padding:0.35rem 0.85rem;">✓ Cursor</span>
            <span class="client-chip" style="font-size:0.85rem;padding:0.35rem 0.85rem;">✓ VS Code / Cline</span>
            <span style="border-left:1px solid var(--border);height:20px;margin:0 0.25rem;"></span>
            ${langBadge(server.language || 'TypeScript')}
            <span class="badge badge-default">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
              ${stars} stars
            </span>
            <span class="badge badge-default">⬇ ${installs} installs</span>
            <span class="badge badge-default">License: ${server.license || 'MIT'}</span>
            <span class="badge badge-cyan">Transport: ${server.transport || 'stdio'}</span>
          </div>
        `;
      }

      // Overview tab
      const overviewEl = document.getElementById('tab-overview');
      if (overviewEl) {
        overviewEl.innerHTML = `
          <div class="doc-box">
            <h3>Documentation</h3>
            <div class="callout-box">
              <strong>Research Notice:</strong> This server is fully instrumented for security research. Switch to the <strong>Tools</strong> tab to inspect tool schemas and test execution boundaries.
            </div>
            <div style="margin-top:1.5rem;line-height:1.75;color:var(--text-2);white-space:pre-line;">
              ${server.long_description || server.description || 'No extended documentation provided.'}
            </div>
          </div>
          <div class="doc-box">
            <h3>Tags & Categories</h3>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-top:0.75rem;">
              ${tagsList.map(t => tagBadge(t)).join('')}
            </div>
          </div>
        `;
      }

      // Install tab
      const installEl = document.getElementById('tab-install');
      if (installEl) installEl.innerHTML = Components.createInstallConfig(server);

      // Sidebar
      const sidebarEl = document.getElementById('server-sidebar');
      if (sidebarEl) {
        sidebarEl.innerHTML = `
          <div class="card" style="margin-bottom:1rem;">
            <h3 style="font-size:0.75rem;text-transform:uppercase;color:var(--accent-cyan);letter-spacing:0.06em;border-bottom:1px solid var(--border);padding-bottom:0.65rem;margin-bottom:1rem;">
              Technical Specifications
            </h3>
            <div class="info-property-box">
              <span class="prop-key">Transport</span>
              <span class="prop-val" style="color:var(--accent);">${server.transport || 'stdio'}</span>
            </div>
            <div class="info-property-box">
              <span class="prop-key">Language</span>
              <span class="prop-val">${server.language || 'TypeScript'}</span>
            </div>
            <div class="info-property-box">
              <span class="prop-key">Hosting</span>
              <span class="prop-val">${server.hosting || 'Local'}</span>
            </div>
            <div class="info-property-box">
              <span class="prop-key">Version</span>
              <span class="prop-val">${server.version || 'v1.0.0'}</span>
            </div>
            <div class="info-property-box">
              <span class="prop-key">License</span>
              <span class="prop-val">${server.license || 'MIT'}</span>
            </div>
            <div class="info-property-box">
              <span class="prop-key">Category</span>
              <span class="prop-val">
                <a href="/servers.html?category=${server.category_slug || ''}" style="color:var(--accent-cyan);">
                  ${server.category_name || 'Developer Tools'}
                </a>
              </span>
            </div>
            <div class="info-property-box">
              <span class="prop-key">Publisher</span>
              <span class="prop-val">${authorName}</span>
            </div>
          </div>

          <div class="card" style="margin-bottom:1rem;">
            <h3 style="font-size:0.75rem;text-transform:uppercase;color:var(--accent-cyan);letter-spacing:0.06em;border-bottom:1px solid var(--border);padding-bottom:0.65rem;margin-bottom:1rem;">
              Client Compatibility
            </h3>
            <div class="info-property-box" style="background:rgba(16,185,129,0.06);border-color:rgba(16,185,129,0.2);">
              <span class="prop-key">Claude Desktop</span>
              <span class="prop-val" style="color:var(--accent);">● Native</span>
            </div>
            <div class="info-property-box" style="background:rgba(16,185,129,0.06);border-color:rgba(16,185,129,0.2);">
              <span class="prop-key">Cursor / Windsurf</span>
              <span class="prop-val" style="color:var(--accent);">● Ready</span>
            </div>
            <div class="info-property-box" style="background:rgba(16,185,129,0.06);border-color:rgba(16,185,129,0.2);">
              <span class="prop-key">VS Code / Cline</span>
              <span class="prop-val" style="color:var(--accent);">● Verified</span>
            </div>
          </div>

          <div class="card" style="background:#04090c;border-color:rgba(239,68,68,0.2);">
            <h3 style="font-size:0.75rem;text-transform:uppercase;color:#f87171;letter-spacing:0.06em;border-bottom:1px solid rgba(255,255,255,0.07);padding-bottom:0.65rem;margin-bottom:1rem;">
              🛡️ Security Scorecard
            </h3>
            <div style="font-size:0.8125rem;display:flex;flex-direction:column;gap:0.5rem;margin-bottom:1rem;">
              <div style="display:flex;justify-content:space-between;">
                <span style="color:var(--text-3);">Sandbox Boundary</span>
                <strong style="color:var(--accent);">Isolated</strong>
              </div>
              <div style="display:flex;justify-content:space-between;">
                <span style="color:var(--text-3);">Input Inspection</span>
                <strong style="color:var(--accent);">Schema Enforced</strong>
              </div>
              <div style="display:flex;justify-content:space-between;">
                <span style="color:var(--text-3);">Threat Test</span>
                <strong style="color:var(--accent-cyan);">Simulator Active</strong>
              </div>
            </div>
            <div class="callout-box" style="margin:0;font-size:0.775rem;border-color:var(--accent);background:rgba(16,185,129,0.06);color:#a5f3fc;">
              <strong>Test Bench:</strong> Click <em>Test Tool</em> in the Tools tab to run custom execution payloads.
            </div>
          </div>
        `;
      }

      // Load tools
      let tools = null;
      try { tools = await API.getServerTools(slug); } catch (_) {}
      tools = (Array.isArray(tools) && tools.length) ? tools : (MOCK_TOOLS_BY_SERVER[slug] || []);

      const toolsEl = document.getElementById('tab-tools');
      if (toolsEl) {
        // Update tab badge
        const toolTab = document.querySelector('[data-target="tab-tools"]');
        if (toolTab) {
          const badge = toolTab.querySelector('.tab-badge');
          if (badge) badge.textContent = tools.length;
        }

        toolsEl.innerHTML = tools.length
          ? tools.map(t => Components.createToolCard(t)).join('')
          : Components.createEmptyState('No tools exposed', 'This server does not expose any MCP tools yet.');
      }

      // Tabs logic
      document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', (e) => {
          document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
          document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
          const target = e.currentTarget.dataset.target;
          e.currentTarget.classList.add('active');
          document.getElementById(target)?.classList.add('active');
        });
      });

    } catch (err) {
      console.error('Server detail error:', err);
      const hdr = document.getElementById('server-header');
      if (hdr) hdr.innerHTML = `<h1>Server Not Found</h1><p>The server you're looking for doesn't exist or couldn't be loaded.</p><a href="/servers.html" class="btn btn-primary">Browse All Servers</a>`;
    }
  },

  async trackInstall(slug) {
    try { await API.installServer(slug, 'claude_desktop'); } catch (_) {}
    this.showToast('Install configuration ready on the Install tab!', 'success');
    document.querySelector('[data-target="tab-install"]')?.click();
  },

  /* ---- Publish Page ---- */
  async initPublishPage() {
    const form = document.getElementById('publish-form');
    if (!form) return;

    API.getCategories().catch(() => MOCK_CATEGORIES).then(cats => {
      const select = document.getElementById('server-category');
      if (!select) return;
      const list = Array.isArray(cats) ? cats : MOCK_CATEGORIES;
      list.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.slug;
        opt.textContent = c.name;
        select.appendChild(opt);
      });
    });

    let tools = [];

    document.getElementById('add-tool-btn')?.addEventListener('click', () => {
      tools.push({ name: '', description: '', inputSchema: {} });
      this.renderToolsForm(tools);
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      btn.textContent = 'Publishing…';

      const formData = new FormData(form);
      const data = Object.fromEntries(formData.entries());
      data.tools = tools;
      data.tags  = data.tags ? data.tags.split(',').map(t => t.trim()).filter(Boolean) : [];

      try {
        const res = await API.publishServer(data);
        this.showToast('Server published successfully! 🎉', 'success');
        window.location.href = `/server-detail.html?slug=${res.slug || data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
      } catch (err) {
        this.showToast(err.message || 'Failed to publish — please check all fields.', 'error');
        btn.disabled = false;
        btn.textContent = 'Publish Server';
      }
    });
  },

  renderToolsForm(tools) {
    const container = document.getElementById('tools-container');
    if (!container) return;
    container.innerHTML = tools.map((t, idx) => `
      <div class="tool-repeat-block">
        <div class="flex justify-between items-center" style="margin-bottom:1rem;">
          <span class="badge badge-indigo">Tool #${idx + 1}</span>
          <button type="button" class="btn btn-danger btn-sm" onclick="App._removeTool(${idx})">Remove</button>
        </div>
        <div class="form-row" style="margin-bottom:0.875rem;">
          <div class="form-field">
            <label class="label">Tool Name</label>
            <input type="text" class="input" placeholder="e.g. search_files" value="${t.name}"
              onchange="App._updateTool(${idx},'name',this.value)">
          </div>
          <div class="form-field">
            <label class="label">Description</label>
            <input type="text" class="input" placeholder="What does this tool do?" value="${t.description}"
              onchange="App._updateTool(${idx},'description',this.value)">
          </div>
        </div>
        <div class="form-field">
          <label class="label">Input Schema (JSON)</label>
          <textarea class="textarea textarea-code" rows="4" placeholder='{ "type": "object", "properties": { … } }'
            onchange="App._updateTool(${idx},'inputSchema',this.value)">${JSON.stringify(t.inputSchema, null, 2)}</textarea>
        </div>
      </div>
    `).join('');
  },

  _updateTool(idx, field, val) {
    if (!window._publishTools) return;
    if (field === 'inputSchema') {
      try { window._publishTools[idx][field] = JSON.parse(val); } catch (_) {}
    } else {
      window._publishTools[idx][field] = val;
    }
  },

  _removeTool(idx) {
    if (!window._publishTools) return;
    window._publishTools.splice(idx, 1);
    App.renderToolsForm(window._publishTools);
  },

  /* ---- Clients Page ---- */
  async initClientsPage() {
    const grid = document.getElementById('clients-grid');
    if (!grid) return;
    grid.innerHTML = Array(4).fill(Components.createSkeletonCard(240)).join('');

    try {
      const clients = await API.getClients();
      const list    = (Array.isArray(clients) && clients.length) ? clients : MOCK_CLIENTS;
      grid.innerHTML = list.map(c => Components.createClientCard(c)).join('');
    } catch (_) {
      grid.innerHTML = MOCK_CLIENTS.map(c => Components.createClientCard(c)).join('');
    }
  },

  /* ---- Categories Page ---- */
  async initCategoriesPage() {
    const grid    = document.getElementById('categories-grid');
    const countEl = document.getElementById('cat-count');
    if (!grid) return;
    grid.innerHTML = Array(8).fill(Components.createSkeletonCard(180)).join('');

    try {
      const cats = await API.getCategories();
      const list = (Array.isArray(cats) && cats.length) ? cats : MOCK_CATEGORIES;
      if (countEl) countEl.textContent = `${list.length} Categories`;
      grid.innerHTML = list.map(c => Components.createCategoryCard(c)).join('');
    } catch (_) {
      if (countEl) countEl.textContent = `${MOCK_CATEGORIES.length} Categories`;
      grid.innerHTML = MOCK_CATEGORIES.map(c => Components.createCategoryCard(c)).join('');
    }
  },

  /* ---- Login Page ---- */
  async initLoginPage() {
    const form    = document.getElementById('login-form');
    const errorEl = document.getElementById('login-error');

    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (errorEl) errorEl.textContent = '';
      const email    = document.getElementById('email')?.value;
      const password = document.getElementById('password')?.value;
      try {
        await API.login({ email, password });
        window.location.href = '/profile.html';
      } catch (err) {
        if (errorEl) errorEl.textContent = err.message || 'Invalid credentials. Please try again.';
      }
    });
  },

  /* ---- Register Page ---- */
  async initRegisterPage() {
    const form    = document.getElementById('register-form');
    const errorEl = document.getElementById('register-error');

    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (errorEl) errorEl.textContent = '';
      const username  = document.getElementById('username')?.value;
      const email     = document.getElementById('email')?.value;
      const password  = document.getElementById('password')?.value;
      const confirm   = document.getElementById('confirm-password')?.value;

      if (password !== confirm) {
        if (errorEl) errorEl.textContent = 'Passwords do not match';
        return;
      }
      try {
        await API.register({ username, email, password });
        await API.login({ email, password });
        window.location.href = '/profile.html';
      } catch (err) {
        if (errorEl) errorEl.textContent = err.message || 'Registration failed. Please try again.';
      }
    });
  },

  /* ---- Profile Page ---- */
  async initProfilePage() {
    const headerEl  = document.getElementById('profile-header');
    const serversEl = document.getElementById('profile-servers');

    const user = this.currentUser || MOCK_USER;

    const displayName = user.displayName || user.display_name || user.username || 'Developer';
    const username    = user.username || 'user';
    const bio         = user.bio || 'MCP developer and AI tooling enthusiast.';
    const avatarEl    = meshGradientAvatar(username, 'avatar-xl');

    if (headerEl) {
      headerEl.innerHTML = `
        <div style="display:flex;gap:2rem;align-items:flex-start;flex-wrap:wrap;">
          <div class="profile-avatar-wrap">${avatarEl}</div>
          <div style="flex:1;min-width:0;">
            <h2 style="margin-bottom:0.25rem;">${displayName}</h2>
            <p style="color:var(--text-3);margin-bottom:0.75rem;font-size:0.9rem;">@${username}</p>
            <p style="max-width:500px;margin-bottom:1rem;font-size:0.9375rem;">${bio}</p>
            <div class="profile-stats-row">
              <div class="profile-stat">
                <div class="pstat-val">${user.publishedServers || 6}</div>
                <div class="pstat-label">Servers</div>
              </div>
              <div class="profile-stat">
                <div class="pstat-val">${(user.stars || 847).toLocaleString()}</div>
                <div class="pstat-label">Total Stars</div>
              </div>
              <div class="profile-stat">
                <div class="pstat-val">${user.totalInstalls || '12.4k'}</div>
                <div class="pstat-label">Installs</div>
              </div>
            </div>
          </div>
        </div>
      `;
    }

    if (serversEl) {
      serversEl.innerHTML = Array(3).fill(Components.createSkeletonCard(220)).join('');
      try {
        const response = await API.getServers({ author: username });
        const servers  = response?.data || response || [];
        const list     = (Array.isArray(servers) && servers.length) ? servers : MOCK_SERVERS.slice(0, 3);
        serversEl.innerHTML = list.map(s => Components.createServerCard(s)).join('');
      } catch (_) {
        serversEl.innerHTML = MOCK_SERVERS.slice(0, 3).map(s => Components.createServerCard(s)).join('');
      }
    }
  },
};

document.addEventListener('DOMContentLoaded', () => App.init());
