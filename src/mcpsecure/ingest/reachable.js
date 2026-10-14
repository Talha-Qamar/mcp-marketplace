/**
 * MCP Secure — pull back deferred files that the server actually runs
 * ====================================================================
 * select.js holds back code under tests/, examples/, docs/, dist/, build/ …
 * A deferred file is admitted into the bundle when it is reachable:
 *
 *   • a package entrypoint: package.json main / module / bin / exports, or a
 *     pyproject [project.scripts] target; or
 *   • imported (transitively) by an admitted file: Python `import a.b`,
 *     `from a.b import c`, relative `from .x import y`; JS/TS relative
 *     `import … from './x'`, `require('./x')`, `import('./x')`, `export … from`.
 *
 * Static and approximate by design (string imports only), but it closes the
 * obvious hiding places: runtime code moved into examples/, and a committed
 * dist/ bundle that differs from the reviewed src/.
 */

const path = require('path');
const { admitDeferred } = require('./select');

const JS_EXT = ['.ts', '.tsx', '.mts', '.cts', '.js', '.mjs', '.cjs', '.jsx'];
const JS_IMPORT_RES = [
  /\bfrom\s*['"](\.{1,2}\/[^'"]+)['"]/g,
  /\bimport\s*['"](\.{1,2}\/[^'"]+)['"]/g,
  /\brequire\s*\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g,
  /\bimport\s*\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g,
];
const PY_IMPORT_RE = /^[ \t]*import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*)/gm;
// Imported names span lines only inside parentheses: `from a import (b,\n c)`.
const PY_FROM_RE = /^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+(\([^)]*\)|[\w*, \t]+)/gm;

function norm(p) {
  const n = path.posix.normalize(p).replace(/^\.\//, '');
  return n.startsWith('../') || n === '..' ? null : n;
}

function jsCandidates(fromFile, spec) {
  const base = norm(path.posix.join(path.posix.dirname(fromFile), spec));
  if (!base) return [];
  const stem = base.replace(/\.(m|c)?js$|\.jsx$/, ''); // TS imports './x.js' meaning './x.ts'
  const out = [base];
  for (const ext of JS_EXT) out.push(stem + ext, `${base}/index${ext}`);
  return out;
}

function pyModuleCandidates(roots, dotted) {
  const rel = dotted.replace(/\./g, '/');
  const out = [];
  for (const r of roots) {
    const p = r ? `${r}/${rel}` : rel;
    out.push(`${p}.py`, `${p}/__init__.py`);
  }
  return out;
}

function pyCandidates(fromFile, text) {
  const dir = path.posix.dirname(fromFile);
  // Absolute imports resolve from the repo root, src/, and every ancestor of the importing file.
  const roots = new Set(['', 'src']);
  for (let d = dir; d && d !== '.'; d = path.posix.dirname(d)) roots.add(d);
  const out = [];
  for (const m of text.matchAll(PY_IMPORT_RE)) {
    for (const mod of m[1].split(',').map(x => x.trim()).filter(Boolean)) {
      const parts = mod.split('.');
      for (let i = 1; i <= parts.length; i++) out.push(...pyModuleCandidates(roots, parts.slice(0, i).join('.')));
    }
  }
  for (const m of text.matchAll(PY_FROM_RE)) {
    const [, dots, mod, names] = m;
    const imported = names.replace(/[()]/g, '').split(',').map(x => x.trim().split(/\s+as\s+/)[0]).filter(x => x && x !== '*');
    if (dots) {
      let base = dir === '.' ? '' : dir;
      for (let i = 1; i < dots.length; i++) base = path.posix.dirname(base) === '.' ? '' : path.posix.dirname(base);
      const target = [base, mod.replace(/\./g, '/')].filter(Boolean).join('/');
      out.push(`${target}.py`, `${target}/__init__.py`);
      for (const n of imported) out.push(`${target ? target + '/' : ''}${n}.py`, `${target ? target + '/' : ''}${n}/__init__.py`);
    } else if (mod) {
      out.push(...pyModuleCandidates(roots, mod));
      for (const n of imported) out.push(...pyModuleCandidates(roots, `${mod}.${n}`));
    }
  }
  return out.map(norm).filter(Boolean);
}

function entrypoints(metadataFiles) {
  const out = [];
  const pkg = metadataFiles.find(f => f.path === 'package.json');
  if (pkg) {
    try {
      const j = JSON.parse(pkg.content);
      const strings = v => (typeof v === 'string' ? [v] : v && typeof v === 'object' ? Object.values(v).flatMap(strings) : []);
      for (const field of ['main', 'module', 'bin', 'exports']) {
        for (const s of strings(j[field])) {
          const n = norm(s);
          if (n) out.push({ candidates: [n, ...JS_EXT.map(e => n + e)], reason: `package.json ${field}` });
        }
      }
    } catch (_) { /* malformed package.json: no entrypoints */ }
  }
  const py = metadataFiles.find(f => f.path === 'pyproject.toml');
  if (py) {
    const section = (py.content.match(/\[project\.scripts\]([\s\S]*?)(?:\n\[|$)/) || [])[1] || '';
    for (const m of section.matchAll(/=\s*["']([\w.]+):[\w.]+["']/g)) {
      out.push({ candidates: pyModuleCandidates(['', 'src'], m[1]), reason: 'pyproject [project.scripts]' });
    }
  }
  return out;
}

function importCandidates(file) {
  if (file.language === 'python') return pyCandidates(file.path, file.content);
  const out = [];
  for (const re of JS_IMPORT_RES) for (const m of file.content.matchAll(re)) out.push(...jsCandidates(file.path, m[1]));
  return out;
}

/**
 * Admit reachable deferred files into `selection.files` (mutates the selection).
 * @returns {{ admitted: {path, reason}[] }}
 */
function admitReachable(selection) {
  const deferred = new Map(selection.deferred.map(d => [d.path, d]));
  const state = { totalBytes: selection.totalBytes || 0 };
  const admitted = [];
  const queue = [...selection.files];

  const admit = (candidates, reason) => {
    for (const c of candidates) {
      const entry = deferred.get(c);
      if (!entry) continue;
      deferred.delete(c);
      const r = admitDeferred(entry, state);
      if (r.skipped) {
        selection.skippedCode.push({ path: c, reason: `${r.skipped} (reachable: ${reason})`, sha256: r.sha256 });
      } else {
        selection.files.push(r.file);
        queue.push(r.file);
        admitted.push({ path: c, reason });
      }
      return;
    }
  };

  for (const ep of entrypoints(selection.metadataFiles)) admit(ep.candidates, ep.reason);
  while (queue.length) {
    const f = queue.shift();
    for (const c of importCandidates(f)) admit([c], `imported by ${f.path}`);
  }
  selection.files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  selection.totalBytes = state.totalBytes;
  return { admitted };
}

module.exports = { admitReachable, pyCandidates, jsCandidates, entrypoints };
