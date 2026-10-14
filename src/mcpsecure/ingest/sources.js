/**
 * MCP Secure — Ingestion sources (spec §4.1, §4.2)
 * =================================================
 * Turns a source reference into a directory on disk plus pinned provenance.
 *
 *   git    https repo URL + ref  → ref resolved to a commit SHA BEFORE fetching
 *   files  [{path, content}]      → written to a temp dir (uploads, API callers)
 *   local  directory path         → demo servers, tests, evaluation (dev only)
 *
 * Candidate code is hostile. Nothing here executes it: git never runs hooks
 * on fetch/checkout, symlinks are checked out as plain files, submodules and
 * LFS objects are never fetched.
 */

const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { promisify } = require('util');
const { sha256Hex, canonicalJson } = require('../canonical');

const execFileAsync = promisify(execFile);

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const GIT_TIMEOUT_MS = Number(process.env.MCS_GIT_TIMEOUT_MS || 120000);
const SHA_RE = /^[0-9a-f]{40}$/;
// No leading '-' (would be parsed as a git option) and no '..' path segments.
const REF_RE = /^(?!-)(?!.*\.\.)[A-Za-z0-9_.\/-]{1,200}$/;
// Git hosts candidates may be fetched from. Anything else (internal hosts, IP
// literals, cloud metadata endpoints) is refused before any network access.
const ALLOWED_GIT_HOSTS = new Set((process.env.MCS_GIT_HOSTS || 'github.com,gitlab.com,bitbucket.org,codeberg.org')
  .split(',').map(h => h.trim().toLowerCase()).filter(Boolean));
// https://github.com/<owner>/<repo>[.git][/tree/<ref>[/<subdir>]]
const GITHUB_RE = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:\/tree\/([^/]+)(?:\/(.+?))?)?\/?$/;
const GENERIC_HTTPS_RE = /^https:\/\/([A-Za-z0-9.-]+)\/([A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)+?)(?:\.git)?\/?$/;

class IngestError extends Error {
  constructor(message, code = 'INGEST_FAILED') {
    super(message);
    this.code = code;
  }
}

function gitEnv() {
  return {
    PATH: process.env.PATH,
    HOME: os.tmpdir(),
    GIT_TERMINAL_PROMPT: '0',
    GIT_ASKPASS: 'true',
    GIT_LFS_SKIP_SMUDGE: '1',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
  };
}

// Every git invocation gets these. core.symlinks=false checks symlinks out as
// small text files instead of links, so nothing can point outside the checkout.
const GIT_HARDENING = [
  '-c', 'credential.helper=',
  '-c', 'core.symlinks=false',
  '-c', 'core.hooksPath=/dev/null',
  '-c', 'protocol.allow=never',
  '-c', 'protocol.https.allow=always',
  '-c', 'submodule.recurse=false',
];

async function git(args, opts = {}) {
  try {
    const { stdout } = await execFileAsync('git', [...GIT_HARDENING, ...args], {
      env: gitEnv(),
      timeout: GIT_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024,
      ...opts,
    });
    return stdout;
  } catch (err) {
    if (err.killed || err.signal === 'SIGTERM') {
      const sub = args.find(a => /^[a-z][a-z-]*$/.test(a)) || '';
      throw new IngestError(`git ${sub} timed out after ${GIT_TIMEOUT_MS / 1000}s (repository too large or network too slow)`);
    }
    const detail = String(err.stderr || err.message || '').trim().split('\n').slice(-2).join(' ');
    throw new IngestError(`git ${args[0]} failed: ${detail.slice(0, 300)}`);
  }
}

/**
 * Normalise a repository URL. GitHub `/tree/<ref>/<subdir>` links are split
 * into repo + ref + subdir, because many real MCP servers live in monorepos.
 */
function parseRepoUrl(url, ref) {
  const raw = String(url || '').trim();
  if (ref !== undefined && ref !== null && ref !== '' && !REF_RE.test(String(ref))) throw new IngestError('invalid ref', 'BAD_SOURCE');
  const gh = raw.match(GITHUB_RE);
  if (gh) {
    if (gh[4] && gh[4].split('/').some(seg => seg === '..' || seg === '.')) throw new IngestError('invalid repository path', 'BAD_SOURCE');
    if (gh[3] && !REF_RE.test(gh[3])) throw new IngestError('invalid ref', 'BAD_SOURCE');
    return {
      repoUrl: `https://github.com/${gh[1]}/${gh[2]}`,
      cloneUrl: `https://github.com/${gh[1]}/${gh[2]}.git`,
      ref: ref || gh[3] || null,
      subdir: gh[4] || null,
    };
  }
  const generic = raw.match(GENERIC_HTTPS_RE);
  if (generic && ALLOWED_GIT_HOSTS.has(generic[1].toLowerCase()) && !generic[2].split('/').includes('..')) {
    return { repoUrl: raw.replace(/\/$/, ''), cloneUrl: raw, ref: ref || null, subdir: null };
  }
  if (generic) throw new IngestError(`git host '${generic[1]}' is not allowed (allowed: ${[...ALLOWED_GIT_HOSTS].join(', ')})`, 'BAD_SOURCE');
  throw new IngestError('repo_url must be a public https git URL (e.g. https://github.com/<owner>/<repo>)', 'BAD_SOURCE');
}

/** Resolve a branch/tag/HEAD to a full commit SHA without fetching any objects. */
async function resolveCommit(cloneUrl, ref) {
  if (ref && SHA_RE.test(ref)) return ref;
  if (ref && !REF_RE.test(ref)) throw new IngestError('invalid ref', 'BAD_SOURCE');
  const want = ref || 'HEAD';
  const out = await git(['ls-remote', '--', cloneUrl, want, `refs/heads/${want}`, `refs/tags/${want}`, `refs/tags/${want}^{}`]);
  const lines = out.split('\n').filter(Boolean).map(l => l.split('\t'));
  if (lines.length === 0) throw new IngestError(`ref '${want}' not found in ${cloneUrl}`);
  // Prefer the peeled tag (^{}) so an annotated tag pins the commit, not the tag object.
  const peeled = lines.find(([, name]) => name.endsWith('^{}'));
  return (peeled || lines[0])[0];
}

function mkWorkdir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function rmrf(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) { /* best effort */ }
}

async function materializeGit(source) {
  const parsed = parseRepoUrl(source.repo_url, source.ref);
  const commitSha = await resolveCommit(parsed.cloneUrl, parsed.ref);
  const dir = mkWorkdir('mcs-git-');
  try {
    await git(['init', '-q', dir]);
    await git(['-C', dir, 'remote', 'add', 'origin', parsed.cloneUrl]);
    await git(['-C', dir, 'fetch', '-q', '--depth', '1', '--no-tags', '--no-recurse-submodules', 'origin', commitSha]);
    await git(['-C', dir, 'checkout', '-q', '--detach', 'FETCH_HEAD']);
  } catch (err) {
    rmrf(dir);
    throw err;
  }
  const root = parsed.subdir ? path.join(dir, parsed.subdir) : dir;
  if (!root.startsWith(dir + path.sep) && root !== dir) { rmrf(dir); throw new IngestError('invalid subdir', 'BAD_SOURCE'); }
  if (!fs.existsSync(root)) { rmrf(dir); throw new IngestError(`path '${parsed.subdir}' not found at ${commitSha.slice(0, 12)}`); }
  return {
    root,
    cleanup: () => rmrf(dir),
    info: {
      kind: 'git',
      repo_url: parsed.repoUrl,
      ref: parsed.ref || 'HEAD',
      subdir: parsed.subdir,
      commit_sha: commitSha,
      archive_sha256: null,
    },
  };
}

function safeRelative(p) {
  const rel = path.posix.normalize(String(p || '').replace(/\\/g, '/')).replace(/^\/+/, '');
  if (!rel || rel === '.' || rel.split('/').includes('..')) return null;
  return rel;
}

async function materializeFiles(source) {
  const files = Array.isArray(source.files) ? source.files : [];
  if (files.length === 0) throw new IngestError('files source needs at least one file', 'BAD_SOURCE');
  const dir = mkWorkdir('mcs-files-');
  const kept = [];
  for (const f of files) {
    const rel = safeRelative(f.path);
    if (!rel || typeof f.content !== 'string') continue; // zip-slip style paths are dropped
    const dest = path.join(dir, rel);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, f.content, 'utf8');
    kept.push({ path: rel, sha256: sha256Hex(f.content) });
  }
  kept.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return {
    root: dir,
    cleanup: () => rmrf(dir),
    info: {
      kind: 'upload',
      repo_url: source.repo_url || null,
      ref: null,
      subdir: null,
      commit_sha: null,
      archive_sha256: sha256Hex(canonicalJson(kept)),
    },
  };
}

/**
 * Local directories are for demo servers, tests and evaluation only.
 * `overlay` (demo only) is a second directory whose files replace the
 * originals — that is how the bait-and-switch demo produces a "new version".
 */
async function materializeLocal(source) {
  if (process.env.MCS_ALLOW_LOCAL_SOURCES === '0') {
    throw new IngestError('local sources are disabled on this deployment', 'BAD_SOURCE');
  }
  // Relative paths are relative to the repository root, not the process cwd.
  const base = path.resolve(REPO_ROOT, source.path || '');
  if (!fs.existsSync(base) || !fs.statSync(base).isDirectory()) {
    throw new IngestError(`local path not found: ${source.path}`, 'BAD_SOURCE');
  }
  let root = base;
  let cleanup = () => {};
  if (source.overlay) {
    const overlay = path.resolve(REPO_ROOT, source.overlay);
    root = mkWorkdir('mcs-local-');
    fs.cpSync(base, root, { recursive: true, verbatimSymlinks: true });
    fs.cpSync(overlay, root, { recursive: true, force: true, verbatimSymlinks: true });
    const tmp = root;
    cleanup = () => rmrf(tmp);
  }
  return {
    root,
    cleanup,
    info: {
      kind: 'local',
      repo_url: source.repo_url || null,
      ref: source.overlay ? 'overlay' : null,
      subdir: null,
      commit_sha: null,
      archive_sha256: null,
    },
  };
}

async function materialize(source) {
  switch (source && source.kind) {
    case 'git': return materializeGit(source);
    case 'files':
    case 'upload': return materializeFiles(source);
    case 'local': return materializeLocal(source);
    default: throw new IngestError(`unknown source kind '${source && source.kind}'`, 'BAD_SOURCE');
  }
}

module.exports = { materialize, parseRepoUrl, resolveCommit, IngestError, safeRelative, REPO_ROOT };
