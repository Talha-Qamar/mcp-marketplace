/**
 * MCP Secure — Ingestion (spec §4)
 * =================================
 * ingest({ source, listing, declaredTools }) → AnalysisBundle
 *
 * The only pipeline stage that touches the outside world. It pins the source
 * (real commit SHA for git), selects files with the one shared filter,
 * discovers MCP tools statically, and computes the content fingerprint over
 * the CODE as well as the descriptions — so a rug pull that swaps only the
 * implementation changes the fingerprint.
 *
 * Every analyzer reads this bundle; none of them fetches anything itself.
 */

const { spawn } = require('child_process');
const path = require('path');
const { materialize, IngestError } = require('./sources');
const { selectFiles } = require('./select');
const { admitReachable, toolReachableFiles, handlerCalls } = require('./reachable');
const { discoverTypeScript } = require('./discover/typescript');
const { canonicalDigest } = require('../canonical');

const BUNDLE_VERSION = '1';
const DISCOVER_PY = path.join(__dirname, 'discover', 'discover_tools.py');
const AST_SRC = path.join(__dirname, '..', '..', '..', 'ast_taint_analyzer', 'src');
const PY_TIMEOUT_MS = 60000;

function pythonBin() {
  return process.env.MCS_PYTHON || 'python3';
}

/** Run the stdlib-only Python discoverer. It parses; it never imports the candidate. */
function discoverPython(files) {
  if (files.length === 0) return Promise.resolve({ tools: [], notes: [] });
  return new Promise((resolve) => {
    const child = spawn(pythonBin(), [DISCOVER_PY], {
      env: { PATH: process.env.PATH, PYTHONPATH: AST_SRC, PYTHONDONTWRITEBYTECODE: '1', PYTHONIOENCODING: 'utf-8' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), PY_TIMEOUT_MS);
    child.stdout.on('data', d => { out += d; });
    child.stderr.on('data', d => { err += d; });
    child.on('error', e => {
      clearTimeout(timer);
      resolve({ tools: [], notes: [`python tool discovery unavailable: ${e.message}`] });
    });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0) {
        resolve({ tools: [], notes: [`python tool discovery failed: ${err.trim().split('\n').pop() || `exit ${code}`}`] });
        return;
      }
      try {
        resolve(JSON.parse(out));
      } catch (e) {
        resolve({ tools: [], notes: [`python tool discovery returned invalid JSON: ${e.message}`] });
      }
    });
    child.stdin.end(JSON.stringify({ files: files.map(f => ({ path: f.path, content: f.content })) }));
  });
}

function assignToolIds(tools) {
  const seen = new Map();
  for (const t of tools) seen.set(`${t.file}#${t.name}`, (seen.get(`${t.file}#${t.name}`) || 0) + 1);
  return tools.map(t => {
    const base = `${t.file}#${t.name}`;
    return { tool_id: seen.get(base) > 1 ? `${base}@${t.handler.start_line}` : base, ...t };
  });
}

function toolLanguage(file, files) {
  const f = files.find(x => x.path === file);
  return f ? f.language : 'python';
}

/** The fingerprint covers code, tools and listing text; provenance is excluded (spec §4.6). */
function contentFingerprint(bundle) {
  return canonicalDigest({
    bundle_version: bundle.bundle_version,
    server: { name: bundle.server.name, description: bundle.server.description },
    files: bundle.files.map(f => ({ path: f.path, sha256: f.sha256 })),
    skipped_code: (bundle.coverage.skipped_code || []).map(f => ({ path: f.path, sha256: f.sha256 })),
    tools: bundle.tools.map(t => ({
      name: t.name, description: t.description, input_schema: t.input_schema, file: t.file, handler: t.handler,
    })),
  });
}

/**
 * @param {object} req
 * @param {object} req.source         { kind: 'git', repo_url, ref } | { kind: 'files', files } | { kind: 'local', path, overlay? }
 * @param {object} [req.listing]      { name, description, declared_language }
 * @param {object[]} [req.declaredTools] tools the publisher says the server has: [{ name, description }]
 * @returns {Promise<object>} AnalysisBundle
 */
async function ingest({ source, listing = {}, declaredTools = [] }) {
  const workspace = await materialize(source);
  try {
    const selection = selectFiles(workspace.root);
    const { admitted } = admitReachable(selection);
    const { files, metadataFiles, skippedCode, notes } = selection;
    for (const a of admitted) notes.push(`included ${a.path} from a skipped directory (${a.reason})`);
    if (skippedCode.length) notes.push(`${skippedCode.length} code file(s) not analysed because of size/count limits`);

    const py = files.filter(f => f.language === 'python');
    const tsjs = files.filter(f => f.language !== 'python');
    const [pyFound, tsFound] = await Promise.all([discoverPython(py), Promise.resolve(discoverTypeScript(tsjs))]);
    notes.push(...pyFound.notes, ...tsFound.notes);

    const discovered = [...pyFound.tools, ...tsFound.tools]
      .map(t => ({ ...t, language: toolLanguage(t.file, files) }))
      .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.handler.start_line - b.handler.start_line || (a.name < b.name ? -1 : 1)));
    const byPath = new Map(files.map(f => [f.path, f]));
    const tools = assignToolIds(discovered).map(t => ({
      tool_id: t.tool_id,
      name: t.name,
      description: t.description,
      description_resolved: t.description_resolved,
      input_schema: t.input_schema,
      language: t.language,
      file: t.file,
      handler: t.handler,
      discovered_by: t.discovered_by,
      calls: handlerCalls(byPath.get(t.file), t.handler),
    }));
    // Which code files tool input can reach (policy: findings elsewhere are evidence only).
    const reachable = toolReachableFiles(files, tools, metadataFiles);
    for (const f of files) f.tool_reachable = reachable ? reachable.has(f.path) : null;

    let toolDiscovery = 'full';
    if (tools.length === 0) toolDiscovery = 'none';
    else if (tools.some(t => !t.description_resolved) || notes.some(n => /parse (errors|failed)/.test(n))) toolDiscovery = 'partial';
    if (files.length === 0) notes.push('no Python/TypeScript/JavaScript source files found');
    if (tools.some(t => !t.description_resolved)) {
      notes.push(`${tools.filter(t => !t.description_resolved).length} tool description(s) are built at runtime and could not be resolved statically`);
    }

    const bundle = {
      bundle_version: BUNDLE_VERSION,
      content_fingerprint: null,
      server: {
        name: listing.name || '',
        description: listing.description || '',
        declared_language: listing.declared_language || null,
      },
      source: {
        kind: workspace.info.kind,
        repo_url: workspace.info.repo_url,
        ref: workspace.info.ref,
        subdir: workspace.info.subdir,
        commit_sha: workspace.info.commit_sha,
        archive_sha256: workspace.info.archive_sha256,
      },
      files,
      metadata_files: metadataFiles,
      tools,
      declared_tools: (declaredTools || [])
        .filter(t => t && t.name)
        .map(t => ({ name: String(t.name), description: String(t.description || '') }))
        .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0)),
      coverage: {
        tool_discovery: toolDiscovery,
        notes,
        skipped_code: skippedCode,
        unresolved_descriptions: tools.filter(t => !t.description_resolved).map(t => t.tool_id),
      },
    };
    bundle.content_fingerprint = contentFingerprint(bundle);
    return bundle;
  } finally {
    workspace.cleanup();
  }
}

/** Short human summary for logs and the live pipeline UI. */
function describeBundle(bundle) {
  const langs = [...new Set(bundle.files.map(f => f.language))];
  return {
    files: bundle.files.length,
    languages: langs,
    tools: bundle.tools.length,
    toolDiscovery: bundle.coverage.tool_discovery,
    commitSha: bundle.source.commit_sha,
    contentFingerprint: bundle.content_fingerprint,
    notes: bundle.coverage.notes,
  };
}

module.exports = { ingest, describeBundle, contentFingerprint, IngestError, BUNDLE_VERSION };
