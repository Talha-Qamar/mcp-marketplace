/**
 * MCP Secure — File selection (spec §4.3)
 * ========================================
 * The single file filter for the whole pipeline. Analyzers analyse what they
 * are given and do not re-filter.
 *
 * Two kinds of skipped directory:
 *   VENDOR_DIRS  dependencies, VCS data, caches: never read.
 *   DEFER_DIRS   tests, examples, docs, build output (Model B's evaluation
 *                corpus filters). Files there are held back as `deferred`, not
 *                dropped: a candidate can hide runtime code in examples/ or ship
 *                a committed dist/ entrypoint, so ingestion pulls back every
 *                deferred file that is imported or is a package entrypoint
 *                (see reachable.js).
 *
 * Symlinks are never followed or read. A code file dropped for a size or count
 * limit is listed in `skippedCode`; the policy refuses PASS when any exist.
 */

const fs = require('fs');
const path = require('path');
const { sha256Hex } = require('../canonical');

const CODE_EXT = {
  '.py': 'python',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
};

const METADATA_FILES = /^(readme(\.[a-z]+)?|package\.json|pyproject\.toml|requirements[\w.-]*\.txt|server\.json|smithery\.ya?ml|dockerfile)$/i;

const VENDOR_DIRS = new Set([
  'node_modules', '.git', 'vendor', 'venv', '.venv', 'site-packages', '__pycache__', 'coverage',
  '.next', '.tox', '.nox', '.mypy_cache', '.pytest_cache', '.ruff_cache',
]);
const DEFER_DIRS = new Set([
  'dist', 'build', 'out', 'test', 'tests', '__tests__', 'spec', 'e2e', 'example', 'examples',
  'doc', 'docs', 'fixture', 'fixtures',
]);
// bench*, integration-tests, e2e_tests, test-utils, testHelpers, …
const DEFER_DIR_PREFIX = /^bench|[-_]tests?$|^test[-_]?(utils?|helpers?|support)$|^testhelpers?$/i;
const SKIP_FILE = /(\.d\.ts$|\.min\.js$|\.test\.|\.spec\.|_test\.py$|^test_.*\.py$|^conftest\.py$|^setup\.py$)/;

const LIMITS = {
  maxFileBytes: Number(process.env.MCS_MAX_FILE_BYTES || 400_000),
  maxFiles: Number(process.env.MCS_MAX_FILES || 5000),
  maxTotalBytes: Number(process.env.MCS_MAX_BUNDLE_BYTES || 20_000_000),
};

function byPath(a, b) {
  return a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
}

/**
 * Walk `root` and return the code and metadata files to analyse.
 * @returns {{ files: object[], metadataFiles: object[], notes: string[] }}
 */
function selectFiles(root, limits = LIMITS) {
  const files = [];
  const deferred = [];
  const metadataFiles = [];
  const skippedCode = [];
  const notes = [];
  let symlinks = 0;
  let oversize = 0;
  let totalBytes = 0;
  let overTotal = 0;
  let overCount = 0;

  const walk = (dir, rel, inDeferred) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_) {
      notes.push(`unreadable directory: ${rel || '.'}`);
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) { symlinks++; continue; }
      if (entry.isDirectory()) {
        const lower = entry.name.toLowerCase();
        if (VENDOR_DIRS.has(lower)) continue;
        walk(abs, relPath, inDeferred || DEFER_DIRS.has(lower) || DEFER_DIR_PREFIX.test(entry.name));
        continue;
      }
      if (!entry.isFile()) continue;

      const isMeta = METADATA_FILES.test(entry.name) && !rel.includes('/');
      const language = CODE_EXT[path.extname(entry.name).toLowerCase()];
      if (!language && !isMeta) continue;
      const defer = language && (inDeferred || SKIP_FILE.test(entry.name));

      const size = fs.lstatSync(abs).size;
      const tooBig = size > limits.maxFileBytes;
      if (defer) {
        // Read later only if something imports it; record its size for the limit check then.
        deferred.push({ path: relPath, language, size, abs, tooBig });
        continue;
      }
      // Skipped code is hashed (not analysed) so the fingerprint still changes when it does.
      const skip = reason => skippedCode.push({ path: relPath, reason, sha256: sha256Hex(fs.readFileSync(abs)) });
      if (tooBig) { oversize++; if (language) skip(`over ${limits.maxFileBytes} bytes`); continue; }
      if (language && files.length >= limits.maxFiles) { overCount++; skip('file-count limit'); continue; }
      if (totalBytes + size > limits.maxTotalBytes) { overTotal++; if (language) skip('bundle-size limit'); continue; }

      const content = fs.readFileSync(abs, 'utf8');
      totalBytes += size;
      if (language) {
        files.push({ path: relPath, language, sha256: sha256Hex(content), size, content });
      } else {
        metadataFiles.push({ path: relPath, sha256: sha256Hex(content), content });
      }
    }
  };

  walk(root, '', false);

  if (symlinks) notes.push(`skipped ${symlinks} symlink(s): symlinks are never followed`);
  if (oversize) notes.push(`skipped ${oversize} file(s) over ${limits.maxFileBytes} bytes`);
  if (overCount) notes.push(`skipped ${overCount} code file(s) over the ${limits.maxFiles}-file limit`);
  if (overTotal) notes.push(`skipped ${overTotal} file(s) over the ${limits.maxTotalBytes}-byte bundle limit`);

  files.sort(byPath);
  metadataFiles.sort(byPath);
  deferred.sort(byPath);
  return { files, metadataFiles, deferred, skippedCode, notes, totalBytes };
}

/** Read a deferred file that turned out to be reachable, applying the same limits. */
function admitDeferred(entry, state, limits = LIMITS) {
  const sha = () => sha256Hex(fs.readFileSync(entry.abs));
  if (entry.tooBig) return { skipped: `over ${limits.maxFileBytes} bytes`, sha256: sha() };
  if (state.totalBytes + entry.size > limits.maxTotalBytes) return { skipped: 'bundle-size limit', sha256: sha() };
  const content = fs.readFileSync(entry.abs, 'utf8');
  state.totalBytes += entry.size;
  return { file: { path: entry.path, language: entry.language, sha256: sha256Hex(content), size: entry.size, content } };
}

module.exports = { selectFiles, admitDeferred, LIMITS, CODE_EXT };
