const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ingest } = require('../src/mcpsecure/ingest');
const { selectFiles } = require('../src/mcpsecure/ingest/select');
const { discoverTypeScript } = require('../src/mcpsecure/ingest/discover/typescript');

const demo = (name, extra = {}) => ingest({ source: { kind: 'local', path: `demo_servers/${name}`, ...extra }, listing: { name } });

test('discovers the tools of every demo server with real file lines', async () => {
  const w = await demo('weather-tools');
  assert.deepEqual(w.tools.map(t => t.tool_id), ['server.py#get_weather', 'server.py#get_forecast', 'server.py#get_alerts']);
  assert.equal(w.tools[0].handler.start_line, 14); // the @mcp.tool() decorator line
  assert.equal(w.coverage.tool_discovery, 'full');

  const d = await demo('db-helper');
  assert.deepEqual(d.tools.map(t => [t.name, t.discovered_by]), [['query_db', 'ts:tool'], ['list_tables', 'ts:registerTool']]);
  assert.equal(d.tools[0].input_schema.properties.limit.type, 'integer');

  const s = await demo('shell-runner');
  assert.equal(s.tools.length, 2);
});

test('the content fingerprint covers code: a code-only swap changes it', async () => {
  const before = await demo('shell-runner');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-test-'));
  try {
    const code = fs.readFileSync(path.join(__dirname, '..', 'demo_servers/shell-runner/server.py'), 'utf8');
    fs.writeFileSync(path.join(tmp, 'server.py'), code.replace('"run " + query', '"exec " + query'));
    const after = await demo('shell-runner', { overlay: tmp });
    assert.deepEqual(after.tools.map(t => t.description), before.tools.map(t => t.description));
    assert.notEqual(after.content_fingerprint, before.content_fingerprint);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a README-only change leaves the content fingerprint unchanged', async () => {
  const before = await demo('weather-tools');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-test-'));
  try {
    fs.writeFileSync(path.join(tmp, 'README.md'), '# changed docs\n');
    const after = await demo('weather-tools', { overlay: tmp });
    assert.equal(after.content_fingerprint, before.content_fingerprint);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('ingestion is deterministic', async () => {
  const a = await demo('db-helper');
  const b = await demo('db-helper');
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('symlinks are never followed; skipped dirs and test files are excluded', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-test-'));
  try {
    fs.writeFileSync(path.join(tmp, 'server.py'), 'x = 1\n');
    fs.symlinkSync('/etc/passwd', path.join(tmp, 'evil.py'));
    fs.mkdirSync(path.join(tmp, 'node_modules'));
    fs.writeFileSync(path.join(tmp, 'node_modules', 'dep.js'), 'module.exports = 1;\n');
    fs.writeFileSync(path.join(tmp, 'test_server.py'), 'def test(): pass\n');
    const r = selectFiles(tmp);
    assert.deepEqual(r.files.map(f => f.path), ['server.py']);
    assert.ok(r.notes.some(n => /symlink/.test(n)));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('uploaded files with traversal paths are dropped', async () => {
  const b = await ingest({
    source: { kind: 'files', files: [
      { path: '../../etc/evil.py', content: 'import os\n' },
      { path: '/abs/evil.py', content: 'x = 1\n' },
      { path: 'ok/server.py', content: '@mcp.tool()\ndef ping(x: str) -> str:\n    """Ping."""\n    return x\n' },
    ] },
    listing: { name: 'upload' },
  });
  assert.deepEqual(b.files.map(f => f.path), ['abs/evil.py', 'ok/server.py']);
  assert.equal(b.source.kind, 'upload');
  assert.match(b.source.archive_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(b.tools.map(t => t.name), ['ping']);
});

test('python low-level SDK tools are discovered from Tool(...) literals', async () => {
  const src = [
    'import mcp.types as types',
    'from mcp.server import Server',
    'server = Server("x")',
    '@server.list_tools()',
    'async def list_tools():',
    '    return [types.Tool(name="run", description="Run it", inputSchema={"type": "object", "properties": {}})]',
    '@server.call_tool()',
    'async def call_tool(name, arguments):',
    '    return []',
  ].join('\n');
  const b = await ingest({ source: { kind: 'files', files: [{ path: 's.py', content: src }] }, listing: { name: 'x' } });
  assert.deepEqual(b.tools.map(t => [t.name, t.discovered_by, t.handler.name]), [['run', 'python:tool_literal', 'call_tool']]);
});

test('typescript low-level tools and runtime-built descriptions', () => {
  const r = discoverTypeScript([{ path: 'i.ts', language: 'typescript', content: [
    'const D = "Fetch a " + "URL";',
    'server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [',
    '  { name: "fetch", description: D, inputSchema: { type: "object" } },',
    '  { name: "dyn", description: `x ${y}`, inputSchema: { type: "object" } }] }));',
    'server.setRequestHandler(CallToolRequestSchema, async (req) => { return {}; });',
  ].join('\n') }]);
  assert.deepEqual(r.tools.map(t => [t.name, t.description, t.description_resolved]), [['fetch', 'Fetch a URL', true], ['dyn', '', false]]);
});

// Patterns from real servers (eval run1: half the scans found no tools before these).
const ts = (files) => discoverTypeScript(files.map(([p, lines]) => ({ path: p, language: 'typescript', content: lines.join('\n') })));
const pyFiles = (files) => ingest({ source: { kind: 'files', files: files.map(([p, lines]) => ({ path: p, content: lines.join('\n') })) }, listing: { name: 'x' } });

test('typescript: names and descriptions resolve through objects and constants in other files', () => {
  const r = ts([
    ['src/tools/get.ts', ['export const PREFIX = "figma";', 'export const getTool = { name: `${PREFIX}_get`, description: "Get data", run() {} };']],
    ['src/index.ts', ['import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
      'server.registerTool(getTool.name, { description: getTool.description, inputSchema: shape }, handlerFn);']],
  ]);
  assert.deepEqual(r.tools.map(t => [t.name, t.description, t.description_resolved, t.discovered_by]),
    [['figma_get', 'Get data', true, 'ts:registerTool']]);
});

test('typescript: tool definition objects, key-named maps and tool classes in an MCP repo', () => {
  const r = ts([
    ['src/defs.ts', [
      'import { Server } from "@modelcontextprotocol/sdk/server/index.js";',
      'export const kubectlGet = { name: "kubectl_get", description: "Get resources", inputSchema: { type: "object", properties: { kind: { type: "string" } } } };',
      'export const storageDefs = { list_buckets: { description: "List buckets", parameters: listSchema } };',
      'export const docs = { full: { description: "Full detail level", parameters: { mode: "info" } } };',
      'export const cli = { name: "fetch", description: "CLI command", parameters: ["[url]"] };',
      'export class FindTool extends ToolBase { static toolName = "find"; public description = "Run a find"; }',
    ]],
  ]);
  assert.deepEqual(r.tools.map(t => t.name).sort(), ['find', 'kubectl_get', 'list_buckets']);
  assert.deepEqual(r.tools.find(t => t.name === 'kubectl_get').input_schema.properties, { kind: { type: 'string' } });
});

test('typescript: definition objects are not tools in a repo without an MCP SDK', () => {
  const r = ts([['a.ts', ['export const x = { name: "n", description: "d", inputSchema: { type: "object" } };']]]);
  assert.deepEqual(r.tools, []);
});

test('python: mcp.tool()(fn), add_tool(Tool.from_function(...)) and enum tool names', async () => {
  const b = await pyFiles([
    ['pkg/impl.py', ['def arbitrary_query(sql: str) -> str:', '    """Run a query."""', '    return sql']],
    ['pkg/main.py', [
      'from mcp.server.fastmcp import FastMCP',
      'from mcp.server.fastmcp.tools import Tool',
      'from pkg.impl import arbitrary_query',
      'from enum import Enum',
      'class Tools(str, Enum):',
      '    NOW = "get_current_time"',
      'def list_tables(db: str):',
      '    return []',
      'mcp = FastMCP("x")',
      'mcp.tool()(arbitrary_query)',
      'mcp.add_tool(Tool.from_function(list_tables, name="list_tables", description="List tables"))',
      '@server.list_tools()',
      'async def lt():',
      '    return [Tool(name=Tools.NOW.value, description="Now", inputSchema={})]',
    ]],
  ]);
  const got = b.tools.map(t => [t.name, t.file, t.discovered_by, t.description]).sort();
  assert.deepEqual(got, [
    ['arbitrary_query', 'pkg/impl.py', 'python:tool_call', 'Run a query.'],
    ['get_current_time', 'pkg/main.py', 'python:tool_literal', 'Now'],
    ['list_tables', 'pkg/main.py', 'python:add_tool', 'List tables'],
  ]);
  assert.deepEqual(b.tools.find(t => t.name === 'arbitrary_query').input_schema, { type: 'object', properties: { sql: { type: 'string' } }, required: ['sql'] });
});

test('test-helper directories are deferred like tests/', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-sel-'));
  for (const d of ['src', 'packages/integration-tests/src', 'src/testHelpers', 'test-utils']) fs.mkdirSync(path.join(dir, d), { recursive: true });
  for (const f of ['src/a.ts', 'packages/integration-tests/src/b.ts', 'src/testHelpers/c.ts', 'test-utils/d.ts']) fs.writeFileSync(path.join(dir, f), 'export const x = 1;\n');
  const sel = selectFiles(dir);
  assert.deepEqual(sel.files.map(f => f.path), ['src/a.ts']);
  assert.equal(sel.deferred.length, 3);
  fs.rmSync(dir, { recursive: true, force: true });
});
