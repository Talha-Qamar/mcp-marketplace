const test = require('node:test');
const assert = require('node:assert/strict');
const { ingest } = require('../src/mcpsecure/ingest');
const tsTaint = require('../src/mcpsecure/analyzers/builtin/ts_taint');

const HEAD = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nconst server = new McpServer({ name: "x", version: "1" });\n';

async function scan(files) {
  const bundle = await ingest({ source: { kind: 'files', files: Object.entries(files).map(([path, content]) => ({ path, content })) } });
  return tsTaint.analyze(bundle).findings.map(f => `${f.threat}:${f.severity}@${f.location.file}:${f.location.line}`);
}

test('command injection through a helper in another file', async () => {
  const out = await scan({
    'src/index.ts': `${HEAD}import { addFiles } from "./logic.js";\nserver.tool("git_add", "Add", {}, async (args) => {\n  return addFiles(args);\n});\n`,
    'src/logic.ts': 'import { exec } from "child_process";\nimport { promisify } from "util";\nconst run = promisify(exec);\nexport async function addFiles(input) {\n  const cmd = `git add ${input.files}`;\n  return run(cmd);\n}\n',
  });
  assert.deepEqual(out, ['command_injection:high@src/logic.ts:6']);
});

test('execFile with an argv array is not a sink', async () => {
  const out = await scan({ 'src/index.ts': `${HEAD}import { execFile } from "child_process";\nserver.tool("log", "Log", {}, async ({ branch }) => {\n  execFile("git", ["log", branch]);\n});\n` });
  assert.deepEqual(out, []);
});

test('SSRF only when the URL starts with tool input', async () => {
  const out = await scan({ 'src/index.ts': `${HEAD}import axios from "axios";\nserver.tool("a", "A", {}, async ({ url, q }) => {\n  await axios.get(\`https://api.example.com/s?q=\${q}\`);\n  return axios.get(url);\n});\n` });
  assert.deepEqual(out, ['ssrf:medium@src/index.ts:6']);
});

test('a guard call sanitizes the checked variable', async () => {
  const out = await scan({ 'src/index.ts': `${HEAD}import * as fs from "fs/promises";\nserver.tool("r", "R", {}, async ({ p }) => {\n  if (!isPathAllowed(p)) throw new Error("no");\n  return fs.readFile(p, "utf8");\n});\n` });
  assert.deepEqual(out, ['path_traversal:low@src/index.ts:6']);
});

test('SQL built from input is injection; placeholders and bind values are not', async () => {
  const out = await scan({ 'src/index.ts': `${HEAD}server.tool("s", "S", {}, async ({ words, name }) => {\n  const cond = words.map(() => "(name LIKE ?)").join(" OR ");\n  db.prepare(\`SELECT * FROM t WHERE (\${cond})\`).all(...words);\n  db.prepare("SELECT * FROM t WHERE name = ?").all(name);\n  return db.prepare(\`SELECT * FROM t WHERE name = '\${name}'\`).all();\n});\n` });
  assert.deepEqual(out, ['sql_injection:medium@src/index.ts:7']);
});

test('deterministic', async () => {
  const files = { 'src/index.ts': `${HEAD}import { exec } from "child_process";\nserver.tool("x", "X", {}, async ({ c }) => exec(c));\n` };
  assert.deepEqual(await scan(files), await scan(files));
});

test('a method on an unknown object is not linked to a same-named function in another file', async () => {
  const out = await scan({
    'src/index.ts': `${HEAD}server.tool("x", "X", {}, async ({ id }) => {\n  return client.run(id);\n});\n`,
    'scripts/dev.js': 'const { spawn } = require("child_process");\nfunction run(cmd) {\n  return spawn(cmd, [], { shell: true });\n}\n',
  });
  assert.deepEqual(out, []);
});
