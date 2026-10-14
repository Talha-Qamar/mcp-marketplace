/**
 * Ingestion against hostile input: source validation, hiding places and limits.
 * Every case here was a real bypass or hole found by eval/run_adversarial.js.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseRepoUrl } = require('../src/mcpsecure/ingest/sources');
const { ingest } = require('../src/mcpsecure/ingest');
const { selectFiles } = require('../src/mcpsecure/ingest/select');

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-sec-'));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  }
  return dir;
}
const scan = (dir) => ingest({ source: { kind: 'local', path: dir }, listing: { name: 't' } });

test('only public https URLs on allowed git hosts are accepted (no SSRF, no other protocols)', () => {
  for (const bad of [
    'https://169.254.169.254/latest/meta-data', 'https://10.0.0.5/a/b', 'https://localhost/a/b', 'https://internal.corp/a/b',
    'http://github.com/a/b', 'file:///etc/passwd', 'git@github.com:a/b.git', 'ssh://github.com/a/b', 'ext::sh -c touch% /tmp/x',
  ]) {
    assert.throws(() => parseRepoUrl(bad), /not allowed|public https/, bad);
  }
  assert.equal(parseRepoUrl('https://gitlab.com/group/sub/repo').repoUrl, 'https://gitlab.com/group/sub/repo');
});

test('refs and subdirectories cannot inject git options or escape the checkout', () => {
  for (const ref of ['--upload-pack=touch /tmp/x', '-x', 'a/../../b', '..']) {
    assert.throws(() => parseRepoUrl('https://github.com/a/b', ref), /invalid ref/, ref);
  }
  assert.throws(() => parseRepoUrl('https://github.com/a/b/tree/main/../../etc'), /invalid repository path/);
  assert.equal(parseRepoUrl('https://github.com/a/b', 'v1.2.3').ref, 'v1.2.3');
});

test('code moved into a skipped directory is included when the server imports it', async () => {
  const dir = tmpRepo({
    'server.py': 'from mcp.server.fastmcp import FastMCP\nfrom examples.impl import run_job\nmcp = FastMCP("x")\n\n@mcp.tool()\ndef job(n: str) -> int:\n    """Job."""\n    return run_job(n)\n',
    'examples/impl.py': 'import os\n\ndef run_job(name):\n    return os.system("job " + name)\n',
    'examples/unused.py': 'x = 1\n',
    'tests/test_server.py': 'def test(): pass\n',
  });
  try {
    const b = await scan(dir);
    assert.deepEqual(b.files.map(f => f.path), ['examples/impl.py', 'server.py']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('relative JS/TS imports and package.json entrypoints pull files back from dist/', async () => {
  const dir = tmpRepo({
    'package.json': JSON.stringify({ name: 'x', main: 'dist/index.js', bin: { x: './dist/cli.js' } }),
    'src/index.ts': 'import { helper } from "../examples/helper.js";\nexport const a = helper;\n',
    'examples/helper.ts': 'export function helper() { return 1; }\n',
    'dist/index.js': 'require("./server");\n',
    'dist/server.js': 'module.exports = {};\n',
    'dist/cli.js': '#!/usr/bin/env node\n',
    'dist/unreferenced.js': 'module.exports = 2;\n',
  });
  try {
    const b = await scan(dir);
    assert.deepEqual(b.files.map(f => f.path), ['dist/cli.js', 'dist/index.js', 'dist/server.js', 'examples/helper.ts', 'src/index.ts']);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a code file over the size limit is reported as skipped code, never silently dropped', () => {
  const dir = tmpRepo({ 'big.py': '# ' + 'x'.repeat(50) + '\n', 'ok.py': 'x = 1\n' });
  try {
    const r = selectFiles(dir, { maxFileBytes: 20, maxFiles: 100, maxTotalBytes: 1e6 });
    assert.deepEqual(r.files.map(f => f.path), ['ok.py']);
    assert.equal(r.skippedCode.length, 1);
    assert.equal(r.skippedCode[0].path, 'big.py');
    assert.equal(r.skippedCode[0].reason, 'over 20 bytes');
    assert.match(r.skippedCode[0].sha256, /^[0-9a-f]{64}$/); // hashed, so the fingerprint follows it
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('runtime-built descriptions are listed for the policy', async () => {
  const dir = tmpRepo({ 'server.py': 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\nD = open("d.txt").read()\n\n@mcp.tool(description=D)\ndef hi(n: str) -> str:\n    return n\n' });
  try {
    const b = await scan(dir);
    assert.deepEqual(b.coverage.unresolved_descriptions, ['server.py#hi']);
    assert.equal(b.coverage.tool_discovery, 'partial');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('hidden characters in descriptions are flagged by the built-in checks', () => {
  const checks = require('../src/mcpsecure/analyzers/builtin/ingest_checks');
  const tool = (description, params = {}) => ({ tool_id: 's.py#t', name: 't', description, input_schema: { type: 'object', properties: params }, file: 's.py', handler: { name: 't', start_line: 1, end_line: 3 } });
  const run = tools => checks.analyze({ server: { name: 'x', description: 'ok' }, tools, declared_tools: [] }).findings;
  assert.equal(run([tool('Echo text.')]).length, 0);
  assert.equal(run([tool('Echo​ text.')])[0].threat, 'tool_poisoning');
  assert.equal(run([tool('Echo', { a: { type: 'string', description: 'x‮y' } })]).length, 1); // bidi override in a parameter
  assert.equal(run([tool('Echo \u{E0049}\u{E0047}')]).length, 1); // Unicode tag characters
});
