import sys
import os

file_path = "database/seed.js"
with open(file_path, "r") as f:
    lines = f.readlines()

# find start and end
start_idx = -1
end_idx = -1

for i, line in enumerate(lines):
    if "const serversToCreate = [" in line:
        start_idx = i - 1 # include the comment
        break

for i in range(start_idx, len(lines)):
    if "        ]);" in lines[i]:
        end_idx = i
        break

replacement = """    // --- 5. Create Servers from JSON ---
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
        const longDesc = s.long_description || `# ${s.name}\\n\\n${s.description}\\n\\n## Installation\\n\\nAdd this server to your MCP client configuration.\\n\\n## Usage\\n\\nConnect and start using the available tools.`;

        db.run(`
            INSERT INTO servers (id, slug, name, author_id, description, long_description, github_url, npm_package, language, hosting, license, version, stars, forks, install_count, category_id, security_status, is_featured, is_official, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            serverId, s.slug, s.name, authorId, s.description, longDesc,
            s.github_url || '', s.npm_package || '', s.language || 'typescript',
            hosting, license, version,
            s.stars || 0, s.forks || 0, s.install_count || s.installs || 0,
            catId, s.security_status || s.security || 'unverified',
            s.is_featured !== undefined ? s.is_featured : (s.featured || 0), 
            s.is_official !== undefined ? s.is_official : (s.official || 0), 
            now, now
        ]);
"""

if start_idx != -1 and end_idx != -1:
    new_lines = lines[:start_idx] + [replacement] + lines[end_idx+1:]
    with open(file_path, "w") as f:
        f.writelines(new_lines)
    print("Patched successfully!")
else:
    print("Could not find start or end index.")
