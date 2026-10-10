import json
import os
import random
import uuid

categories_data = {
    "ai-agents": [
        {"name": "LangChain Agent", "slug": "langchain-mcp", "cmd": "mcp-langchain"},
        {"name": "LlamaIndex Core", "slug": "llamaindex-mcp", "cmd": "mcp-llamaindex"},
        {"name": "OpenAI Swarm", "slug": "openai-swarm-mcp", "cmd": "swarm-mcp"},
        {"name": "AutoGPT", "slug": "autogpt-mcp", "cmd": "autogpt-server"},
        {"name": "BabyAGI Integrator", "slug": "babyagi-mcp", "cmd": "babyagi-mcp"},
        {"name": "CrewAI Server", "slug": "crewai-mcp", "cmd": "crewai-server"}
    ],
    "app-automation": [
        {"name": "Zapier Hub", "slug": "zapier-mcp", "cmd": "zapier-mcp-hub"},
        {"name": "Make.com Scenarios", "slug": "make-mcp", "cmd": "make-mcp"},
        {"name": "n8n Workflows", "slug": "n8n-mcp", "cmd": "n8n-mcp-server"},
        {"name": "Apple Shortcuts", "slug": "shortcuts-mcp", "cmd": "mac-shortcuts-mcp"},
        {"name": "IFTTT Connector", "slug": "ifttt-mcp", "cmd": "ifttt-mcp"}
    ],
    "communication": [
        {"name": "Slack Integration", "slug": "slack", "cmd": "@modelcontextprotocol/server-slack", "official": True},
        {"name": "Discord Bot", "slug": "discord-mcp", "cmd": "discord-mcp-server"},
        {"name": "Microsoft Teams", "slug": "teams-mcp", "cmd": "teams-mcp"},
        {"name": "Gmail API", "slug": "gmail-mcp", "cmd": "gmail-mcp-server"},
        {"name": "Twilio SMS", "slug": "twilio-mcp", "cmd": "twilio-mcp"},
        {"name": "SendGrid Emailer", "slug": "sendgrid-mcp", "cmd": "sendgrid-mcp"}
    ],
    "databases": [
        {"name": "SQLite", "slug": "sqlite", "cmd": "mcp-server-sqlite", "official": True},
        {"name": "PostgreSQL", "slug": "postgres", "cmd": "@modelcontextprotocol/server-postgres", "official": True},
        {"name": "MySQL", "slug": "mysql-mcp", "cmd": "mysql-mcp"},
        {"name": "MongoDB", "slug": "mongodb-mcp", "cmd": "mongo-mcp"},
        {"name": "Redis Cache", "slug": "redis-mcp", "cmd": "redis-mcp"},
        {"name": "Supabase", "slug": "supabase-mcp", "cmd": "supabase-mcp"}
    ],
    "developer-tools": [
        {"name": "GitHub", "slug": "github", "cmd": "@modelcontextprotocol/server-github", "official": True},
        {"name": "GitLab", "slug": "gitlab-mcp", "cmd": "gitlab-mcp-server"},
        {"name": "Jira Software", "slug": "jira-mcp", "cmd": "jira-mcp"},
        {"name": "Linear", "slug": "linear-mcp", "cmd": "linear-mcp-server"},
        {"name": "Sentry APM", "slug": "sentry-mcp", "cmd": "sentry-mcp"},
        {"name": "Datadog", "slug": "datadog-mcp", "cmd": "datadog-mcp"}
    ],
    "memory-knowledge": [
        {"name": "Memory Graph", "slug": "memory", "cmd": "@modelcontextprotocol/server-memory", "official": True},
        {"name": "Pinecone Vector", "slug": "pinecone-mcp", "cmd": "pinecone-mcp"},
        {"name": "Qdrant", "slug": "qdrant-mcp", "cmd": "qdrant-mcp"},
        {"name": "Weaviate", "slug": "weaviate-mcp", "cmd": "weaviate-mcp"},
        {"name": "Obsidian Vault", "slug": "obsidian-mcp", "cmd": "obsidian-mcp"},
        {"name": "Notion Workspace", "slug": "notion-mcp", "cmd": "notion-mcp"}
    ],
    "search": [
        {"name": "Brave Search", "slug": "brave-search", "cmd": "@modelcontextprotocol/server-brave-search", "official": True},
        {"name": "Tavily Search", "slug": "tavily-mcp", "cmd": "tavily-mcp"},
        {"name": "Exa AI Search", "slug": "exa-mcp", "cmd": "exa-mcp"},
        {"name": "Google Search API", "slug": "google-search-mcp", "cmd": "google-search-mcp"},
        {"name": "Algolia Index", "slug": "algolia-mcp", "cmd": "algolia-mcp"}
    ],
    "system-infra": [
        {"name": "Filesystem", "slug": "filesystem", "cmd": "@modelcontextprotocol/server-filesystem", "official": True},
        {"name": "Kubernetes", "slug": "k8s-mcp", "cmd": "k8s-mcp"},
        {"name": "Docker Engine", "slug": "docker-mcp", "cmd": "docker-mcp"},
        {"name": "AWS EC2/S3", "slug": "aws-mcp", "cmd": "aws-mcp"},
        {"name": "Terraform", "slug": "terraform-mcp", "cmd": "terraform-mcp"},
        {"name": "GCP Cloud", "slug": "gcp-mcp", "cmd": "gcp-mcp"}
    ],
    "web-automation": [
        {"name": "Puppeteer", "slug": "puppeteer", "cmd": "@modelcontextprotocol/server-puppeteer", "official": True},
        {"name": "Playwright", "slug": "playwright-mcp", "cmd": "playwright-mcp"},
        {"name": "Fetch", "slug": "fetch", "cmd": "mcp-server-fetch", "official": True},
        {"name": "Selenium Grid", "slug": "selenium-mcp", "cmd": "selenium-mcp"},
        {"name": "Browser Use", "slug": "browser-use-mcp", "cmd": "browser-use-mcp"}
    ],
    "analytics-data": [
        {"name": "Google Analytics", "slug": "ga-mcp", "cmd": "ga-mcp-server"},
        {"name": "Mixpanel", "slug": "mixpanel-mcp", "cmd": "mixpanel-mcp"},
        {"name": "PostHog", "slug": "posthog-mcp", "cmd": "posthog-mcp"},
        {"name": "Tableau Reports", "slug": "tableau-mcp", "cmd": "tableau-mcp"},
        {"name": "Metabase SQL", "slug": "metabase-mcp", "cmd": "metabase-mcp"},
        {"name": "Snowflake", "slug": "snowflake-mcp", "cmd": "snowflake-mcp"}
    ]
}

def generate_readme(server, category):
    base_readme = f"""# {server['name']} MCP Server

Welcome to the official MCP server for **{server['name']}**. This server allows AI models (like Claude) to interface directly with the {server['name']} platform, executing commands, reading data, and automating workflows.

## 🚀 Features
- **Seamless Integration:** Native support for {category.replace('-', ' ').title()} workflows.
- **Secure Execution:** Runs entirely within your designated client permissions.
- **Robust Tooling:** Provides a comprehensive suite of JSON schema-defined tools.

## 📦 Installation

To install this server, add the following to your MCP client configuration (e.g., `claude_desktop_config.json`):

```json
{{
  "mcpServers": {{
    "{server['slug']}": {{
      "command": "npx",
      "args": ["-y", "{server['cmd']}"]
    }}
  }}
}}
```
*(If using Python, replace `npx` with `uvx` depending on the runtime environment).*

## ⚙️ Configuration
Some tools require environment variables. Ensure the following are set in your client:
- `{server['name'].upper().replace(' ', '_')}_API_KEY`: Your authentication token.
- `LOG_LEVEL`: Set to `debug` for troubleshooting.

## 🛠️ Usage Examples
Once installed, your AI assistant can invoke tools like `get_data`, `run_query`, or `execute_action`. Simply ask your AI:
> "Use the {server['name']} server to fetch the latest updates and summarize them."

## 📜 License
MIT License.
"""
    return base_readme

all_servers = []

for category, s_list in categories_data.items():
    for idx, s in enumerate(s_list):
        is_official = s.get('official', False)
        
        tools = [
            {
                "name": f"get_{s['slug'].replace('-', '_')}_data",
                "description": f"Retrieves primary data or objects from {s['name']}.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "The search or retrieval query."},
                        "limit": {"type": "number", "description": "Maximum number of results to return (default 10)."}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": f"execute_{s['slug'].replace('-', '_')}_action",
                "description": f"Executes a state-changing action or command on {s['name']}.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action_type": {"type": "string", "description": "Type of action to perform."},
                        "payload": {"type": "object", "description": "JSON payload for the action parameters."}
                    },
                    "required": ["action_type", "payload"]
                }
            }
        ]

        # Overwrite with highly specific tools for famous official ones
        if s['slug'] == 'github':
            tools = [
                {
                    "name": "search_repositories",
                    "description": "Search for GitHub repositories.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]
                    }
                },
                {
                    "name": "create_issue",
                    "description": "Create a new issue in a repo.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"owner": {"type": "string"}, "repo": {"type": "string"}, "title": {"type": "string"}},
                        "required": ["owner", "repo", "title"]
                    }
                }
            ]
        elif s['slug'] == 'filesystem':
            tools = [
                {
                    "name": "read_file",
                    "description": "Read file contents.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"]
                    }
                },
                {
                    "name": "write_file",
                    "description": "Write to a file.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                        "required": ["path", "content"]
                    }
                }
            ]
        
        server_obj = {
            "name": s["name"],
            "slug": s["slug"],
            "author_username": "modelcontextprotocol" if is_official else ("community_dev_" + str(idx)),
            "description": f"Powerful integration for {s['name']} providing essential tools and workflows.",
            "long_description": generate_readme(s, category),
            "github_url": f"https://github.com/example/{s['slug']}",
            "npm_package": s['cmd'] if '@' in s['cmd'] else f"mcp-{s['slug']}",
            "language": random.choice(["typescript", "python", "go", "rust"]),
            "hosting": random.choice(["local", "remote"]),
            "license": "MIT",
            "version": f"1.{random.randint(0, 9)}.{random.randint(0, 5)}",
            "category_slug": category,
            "security_status": "verified" if is_official else random.choice(["verified", "unverified"]),
            "is_featured": is_official or random.random() > 0.8,
            "is_official": is_official,
            "stars": random.randint(10, 5000) if is_official else random.randint(0, 500),
            "forks": random.randint(5, 500) if is_official else random.randint(0, 50),
            "installs": random.randint(100, 20000) if is_official else random.randint(10, 2000),
            "tools": tools,
            "resources": [
                {
                    "name": f"{s['name']} Documentation",
                    "description": "Official docs resource.",
                    "uri_template": "docs://{topic}"
                }
            ]
        }
        all_servers.append(server_obj)

os.makedirs('database/data', exist_ok=True)
with open('database/data/massive_real_world.json', 'w') as f:
    json.dump(all_servers, f, indent=4)
print(f"Generated {len(all_servers)} hyper-realistic servers across {len(categories_data.keys())} categories.")
