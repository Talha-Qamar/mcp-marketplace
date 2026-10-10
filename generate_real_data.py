import json
import os

servers = [
    {
        "name": "Brave Search",
        "slug": "brave-search",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server for Brave Search API, enabling AI models to search the web.",
        "long_description": "# Brave Search MCP Server\n\nAn MCP server that provides web search capabilities using the Brave Search API.\n\n## Features\n- **Web Search**: Perform broad web searches\n- **Local Search**: Find local businesses and places\n\n## Installation\n\n```bash\nnpx -y @modelcontextprotocol/server-brave-search\n```\n\n## Configuration\nRequires `BRAVE_API_KEY` environment variable.\n",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/brave-search",
        "npm_package": "@modelcontextprotocol/server-brave-search",
        "language": "typescript",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "search",
        "security_status": "verified",
        "is_featured": True,
        "is_official": True,
        "tools": [
            {
                "name": "brave_web_search",
                "description": "Performs a web search using the Brave Search API, ideal for general queries, news, articles, and web content.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "The search query (e.g. 'latest AI news', 'how to cook pasta')" },
                        "count": { "type": "number", "description": "Number of results (1-20, default 10)" }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "brave_local_search",
                "description": "Searches for local businesses, places, or points of interest using the Brave Local Search API.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "The local search query (e.g. 'pizza near me')" },
                        "count": { "type": "number", "description": "Number of results (1-20, default 5)" }
                    },
                    "required": ["query"]
                }
            }
        ]
    },
    {
        "name": "Filesystem",
        "slug": "filesystem",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server that enables secure local file system access (read, write, list) with restricted directory scopes.",
        "long_description": "# Filesystem MCP Server\n\nProvides secure access to your local filesystem. You must specify which directories the AI is allowed to access.\n\n## Installation\n\n```bash\nnpx -y @modelcontextprotocol/server-filesystem /path/to/allowed/dir\n```\n\n## Security\nBy design, the filesystem server operates only within the explicitly whitelisted paths.",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
        "npm_package": "@modelcontextprotocol/server-filesystem",
        "language": "typescript",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "developer-tools",
        "security_status": "verified",
        "is_featured": True,
        "is_official": True,
        "tools": [
            {
                "name": "read_file",
                "description": "Read the complete contents of a file from the allowed directories.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute path to the file" }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "write_file",
                "description": "Write or overwrite a file in the allowed directories.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute path to the file" },
                        "content": { "type": "string", "description": "Content to write" }
                    },
                    "required": ["path", "content"]
                }
            },
            {
                "name": "list_directory",
                "description": "List files and folders within a given directory.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute path to the directory" }
                    },
                    "required": ["path"]
                }
            }
        ]
    },
    {
        "name": "GitHub",
        "slug": "github",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server for GitHub, enabling AI agents to read repositories, create issues, and manage pull requests.",
        "long_description": "# GitHub MCP Server\n\nInteract directly with GitHub. This server allows reading source code, managing issues, commenting on PRs, and pushing code.\n\n## Setup\nRequires a `GITHUB_PERSONAL_ACCESS_TOKEN`.\n\n```bash\nnpx -y @modelcontextprotocol/server-github\n```\n",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/github",
        "npm_package": "@modelcontextprotocol/server-github",
        "language": "typescript",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "developer-tools",
        "security_status": "verified",
        "is_featured": True,
        "is_official": True,
        "tools": [
            {
                "name": "search_repositories",
                "description": "Search for GitHub repositories using GitHub's search syntax.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query" }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "create_issue",
                "description": "Create a new issue in a GitHub repository.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "owner": { "type": "string", "description": "Repository owner" },
                        "repo": { "type": "string", "description": "Repository name" },
                        "title": { "type": "string", "description": "Issue title" },
                        "body": { "type": "string", "description": "Issue body markdown" }
                    },
                    "required": ["owner", "repo", "title"]
                }
            }
        ]
    },
    {
        "name": "SQLite",
        "slug": "sqlite",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server for querying SQLite databases locally, allowing AI to inspect schemas and run SQL queries.",
        "long_description": "# SQLite MCP Server\n\nRun read-only or read-write SQL queries directly on local SQLite databases.\n\n## Usage\n\n```bash\nuvx mcp-server-sqlite --db-path /path/to/database.db\n```\n",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite",
        "npm_package": "",
        "language": "python",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "databases",
        "security_status": "verified",
        "is_featured": True,
        "is_official": True,
        "tools": [
            {
                "name": "read_query",
                "description": "Execute a SELECT query against the SQLite database.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "The SELECT SQL query to run" }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "list_tables",
                "description": "List all tables in the SQLite database.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    },
    {
        "name": "Slack",
        "slug": "slack",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server for interacting with Slack workspaces, reading channels, and posting messages.",
        "long_description": "# Slack MCP Server\n\nIntegrate AI with your Slack workspace. Read conversations, summarize channels, and send messages.\n\n## Setup\nRequires a `SLACK_BOT_TOKEN`.\n",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/slack",
        "npm_package": "@modelcontextprotocol/server-slack",
        "language": "typescript",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "communication",
        "security_status": "verified",
        "is_featured": True,
        "is_official": True,
        "tools": [
            {
                "name": "slack_list_channels",
                "description": "List all public channels in the Slack workspace.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "limit": { "type": "number", "description": "Max number of channels to return" }
                    }
                }
            },
            {
                "name": "slack_post_message",
                "description": "Post a message to a specific Slack channel.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "channel_id": { "type": "string", "description": "The ID of the channel" },
                        "text": { "type": "string", "description": "The message text" }
                    },
                    "required": ["channel_id", "text"]
                }
            }
        ]
    },
    {
        "name": "PostgreSQL",
        "slug": "postgres",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server for querying PostgreSQL databases. Enables schema introspection and running advanced queries.",
        "long_description": "# PostgreSQL MCP Server\n\nRun SQL queries directly on a remote or local PostgreSQL database.\n\n## Usage\n\n```bash\nnpx -y @modelcontextprotocol/server-postgres postgresql://user:pass@localhost:5432/dbname\n```\n",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/postgres",
        "npm_package": "@modelcontextprotocol/server-postgres",
        "language": "typescript",
        "hosting": "remote",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "databases",
        "security_status": "verified",
        "is_featured": False,
        "is_official": True,
        "tools": [
            {
                "name": "query",
                "description": "Run a read-only SQL query on the PostgreSQL database.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string", "description": "The SQL query string" }
                    },
                    "required": ["sql"]
                }
            }
        ]
    },
    {
        "name": "Memory",
        "slug": "memory",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server providing persistent knowledge graph memory, allowing AI to remember facts across sessions.",
        "long_description": "# Memory MCP Server\n\nA persistent knowledge graph that allows AI models to store and retrieve entities, relations, and observations.\n\n## Usage\n```bash\nnpx -y @modelcontextprotocol/server-memory\n```",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/memory",
        "npm_package": "@modelcontextprotocol/server-memory",
        "language": "typescript",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "memory-knowledge",
        "security_status": "verified",
        "is_featured": True,
        "is_official": True,
        "tools": [
            {
                "name": "add_entity",
                "description": "Add a new entity to the knowledge graph.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "entity_type": { "type": "string" },
                        "observations": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["name", "entity_type"]
                }
            },
            {
                "name": "add_relation",
                "description": "Add a relation between two entities.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "source": { "type": "string" },
                        "target": { "type": "string" },
                        "relation": { "type": "string" }
                    },
                    "required": ["source", "target", "relation"]
                }
            }
        ]
    },
    {
        "name": "Puppeteer",
        "slug": "puppeteer",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server for browser automation via Puppeteer, allowing AI to scrape dynamic content and interact with web pages.",
        "long_description": "# Puppeteer MCP Server\n\nControl a headless Chromium browser using Puppeteer. Useful for scraping SPAs, taking screenshots, and filling out forms.\n\n## Usage\n```bash\nnpx -y @modelcontextprotocol/server-puppeteer\n```",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer",
        "npm_package": "@modelcontextprotocol/server-puppeteer",
        "language": "typescript",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "developer-tools",
        "security_status": "verified",
        "is_featured": False,
        "is_official": True,
        "tools": [
            {
                "name": "navigate",
                "description": "Navigate the browser to a specific URL.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "screenshot",
                "description": "Take a screenshot of the current page.",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    },
    {
        "name": "Fetch",
        "slug": "fetch",
        "author_username": "modelcontextprotocol",
        "description": "Official MCP server for fetching raw content from URLs, converting HTML to Markdown for LLM consumption.",
        "long_description": "# Fetch MCP Server\n\nA simple utility server that fetches web pages and returns them as clean Markdown, optimized for AI models.\n\n## Usage\n```bash\nuvx mcp-server-fetch\n```",
        "github_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/fetch",
        "npm_package": "",
        "language": "python",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.0",
        "category_slug": "search",
        "security_status": "verified",
        "is_featured": False,
        "is_official": True,
        "tools": [
            {
                "name": "fetch_url",
                "description": "Fetch a URL and return its content as Markdown.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" }
                    },
                    "required": ["url"]
                }
            }
        ]
    },
    {
        "name": "Raycast",
        "slug": "raycast",
        "author_username": "community",
        "description": "Community MCP server connecting AI models to Raycast extensions and macOS features.",
        "long_description": "# Raycast MCP Server\n\nControl Raycast extensions and interact with your macOS system via AI.\n",
        "github_url": "https://github.com/raycast/mcp-server-raycast",
        "npm_package": "mcp-server-raycast",
        "language": "typescript",
        "hosting": "local",
        "license": "MIT",
        "version": "1.0.5",
        "category_slug": "app-automation",
        "security_status": "unverified",
        "is_featured": False,
        "is_official": False,
        "tools": [
            {
                "name": "run_extension",
                "description": "Run a Raycast extension command.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "extension_name": { "type": "string" },
                        "command": { "type": "string" }
                    },
                    "required": ["extension_name", "command"]
                }
            }
        ]
    }
]

os.makedirs('database/data', exist_ok=True)
with open('database/data/real-world.json', 'w') as f:
    json.dump(servers, f, indent=4)
print(f"Generated {len(servers)} real-world servers in database/data/real-world.json")
