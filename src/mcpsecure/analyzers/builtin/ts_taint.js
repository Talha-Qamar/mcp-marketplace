/**
 * MCP Secure — TypeScript / JavaScript taint analyzer (built-in, static)
 * =======================================================================
 * The TS/JS counterpart of ast_taint_analyzer/ (Python): does MCP tool input
 * reach a dangerous call? Parses with the TypeScript compiler; never runs,
 * imports or builds the candidate.
 *
 * Sources   parameters of discovered tool handlers (bundle.tools spans), and
 *           the request parameter of setRequestHandler(CallToolRequestSchema, …).
 * Flow      assignments, destructuring, template strings, `+`, string methods,
 *           array/object literals, `.map(x => …)` callbacks on tainted values,
 *           and calls into the server's own functions — same file, imported
 *           from a relative module, or uniquely named — up to MAX_DEPTH calls
 *           deep (inter-procedural, across files).
 * Sinks     child_process exec / shell spawn            → command_injection
 *           eval, new Function, vm.*                     → code_injection
 *           fs.* path arguments                          → path_traversal
 *           fetch / axios / got / http(s) whose URL STARTS
 *           with tool input (who picks the host)         → ssrf
 *           query / execute / raw with a SQL string BUILT
 *           from tool input (template or `+`)            → sql_injection
 *           A bare tool argument passed as the whole query or URL is a tool
 *           that runs queries / fetches URLs by design: reported only as
 *           low-severity evidence, not as injection.
 * Sanitizers  calls named like validate*, sanitize*, escape*, quote*, safe*,
 *           path.basename, encodeURIComponent → the flow is LOW.
 *
 * Deterministic: same bundle, same findings. Approximate by design (name-based
 * call resolution, no path sensitivity); see spec Appendix E.
 */

const ts = require('typescript');
const { canonicalDigest, sha256Hex } = require('../../canonical');

const ID = 'ts_taint';
const VERSION = '0.1.0';
const ARTIFACT_HASH = 'sha256:' + sha256Hex(`${ID}@${VERSION}`);
const MAX_DEPTH = 4;
const MAX_CANDIDATES = 3;
// Wall-clock budget per bundle. Exceeding it never changes a result silently:
// the slot reports status "partial" with a note, and findings so far are kept.
const BUDGET_MS = Number(process.env.MCS_TS_TAINT_BUDGET_MS || 20000);

class BudgetExceeded extends Error {}

const SEVERITY_SCORE = { high: 1.0, medium: 0.55, low: 0.25 };
const THREAT = {
  shell: ['command_injection', 'CWE-78'],
  exec: ['code_injection', 'CWE-94'],
  file: ['path_traversal', 'CWE-22'],
  network: ['ssrf', 'CWE-918'],
  sql: ['sql_injection', 'CWE-89'],
};

const MODULE_ALIASES = {
  'fs/promises': 'fs', 'fs-extra': 'fs', 'graceful-fs': 'fs',
  'node-fetch': 'fetch', 'undici': 'fetch', 'cross-fetch': 'fetch', 'isomorphic-fetch': 'fetch',
  'https': 'http',
};
const FS_PATH_FNS = new Set(['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
  'createReadStream', 'createWriteStream', 'unlink', 'unlinkSync', 'rm', 'rmSync', 'rmdir', 'rmdirSync', 'readdir',
  'readdirSync', 'mkdir', 'mkdirSync', 'stat', 'statSync', 'lstat', 'access', 'open', 'openSync', 'opendir', 'readJson',
  'readJSON', 'writeJson', 'outputFile', 'remove', 'copy', 'move', 'copyFile', 'copyFileSync', 'rename', 'renameSync',
  'cp', 'symlink', 'truncate', 'chmod', 'utimes', 'ensureDir', 'emptyDir']);
const FS_TWO_PATHS = new Set(['copyFile', 'copyFileSync', 'rename', 'renameSync', 'cp', 'symlink', 'copy', 'move']);
const SHELLS = new Set(['sh', 'bash', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'pwsh', '/bin/sh', '/bin/bash']);
const HTTP_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request']);
// Methods whose first argument is SQL text. (.all/.run/.get take bind values, not SQL.)
const SQL_METHODS = new Set(['query', 'execute', 'raw', 'unsafe', '$queryRawUnsafe', '$executeRawUnsafe', 'exec', 'prepare']);
const STRING_METHODS = new Set(['concat', 'replace', 'replaceAll', 'trim', 'trimStart', 'trimEnd', 'toLowerCase',
  'toUpperCase', 'split', 'join', 'slice', 'substring', 'substr', 'padStart', 'padEnd', 'toString', 'valueOf',
  'normalize', 'repeat', 'at', 'map', 'filter', 'flat', 'flatMap', 'reduce', 'find', 'values', 'keys', 'entries']);
const ITERATOR_METHODS = new Set(['map', 'forEach', 'filter', 'flatMap', 'reduce', 'find', 'some', 'every']);
const PROPAGATING_GLOBALS = new Set(['String', 'decodeURIComponent', 'decodeURI', 'JSON.parse', 'JSON.stringify',
  'path.join', 'path.resolve', 'path.normalize', 'path.dirname', 'path.relative', 'Buffer.from', 'Array.from',
  'Object.values', 'Object.entries', 'Object.assign', 'url.fileURLToPath', 'fileURLToPath']);
const SANITIZER_RE = /^(validate|sanitize|sanitise|escape|quote|safe|shellEscape|shellQuote|assert|ensureSafe|isSafe|checkPath|resolveSafe)/i;
// Guards: `validateServerUrl(url);` or `if (!isAllowedPath(p)) throw …` — the
// checked variable is treated as sanitized from that point on.
const GUARD_RE = /^(validate|sanitize|sanitise|assert|ensure|verify|check|guard|is|has)[A-Z_]?\w*?(url|uri|host|path|dir|file|ip|allowed|safe|private|internal|trusted|within|inside|domain|origin)/i;
const SANITIZER_FULL = new Set(['path.basename', 'basename', 'encodeURIComponent', 'encodeURI', 'parseInt', 'parseFloat', 'Number', 'Boolean']);
const NOT_A_SOURCE_METHOD = new Set(['constructor']);

function scriptKind(file) {
  if (/\.tsx$/.test(file)) return ts.ScriptKind.TSX;
  if (/\.(m|c)?ts$/.test(file)) return ts.ScriptKind.TS;
  if (/\.jsx$/.test(file)) return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

function unwrap(node) {
  while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node)
    || ts.isTypeAssertionExpression(node) || ts.isAwaitExpression(node)
    || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(node)))) {
    node = node.expression;
  }
  return node;
}

const isFn = n => ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n);
const lineOf = (sf, pos) => sf.getLineAndCharacterOfPosition(pos).line + 1;

function normModule(spec) {
  let m = String(spec).replace(/^node:/, '');
  return MODULE_ALIASES[m] || m;
}

/** Per-file import table: local name → { mod, member } (member null = namespace/default). */
function importsOf(sf) {
  const table = new Map();
  const visit = node => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && node.importClause) {
      const mod = normModule(node.moduleSpecifier.text);
      const c = node.importClause;
      if (c.name) table.set(c.name.text, { mod, member: null, spec: node.moduleSpecifier.text });
      const nb = c.namedBindings;
      if (nb && ts.isNamespaceImport(nb)) table.set(nb.name.text, { mod, member: null, spec: node.moduleSpecifier.text });
      if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) table.set(el.name.text, { mod, member: (el.propertyName || el.name).text, spec: node.moduleSpecifier.text });
      }
    }
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const init = unwrap(node.initializer);
      const req = init && ts.isCallExpression(init) && ts.isIdentifier(init.expression) && init.expression.text === 'require'
        && init.arguments[0] && ts.isStringLiteral(init.arguments[0]) ? init.arguments[0].text : null;
      // const x = require('m').member
      const reqMember = init && ts.isPropertyAccessExpression(init) && ts.isCallExpression(init.expression)
        && ts.isIdentifier(init.expression.expression) && init.expression.expression.text === 'require'
        && init.expression.arguments[0] && ts.isStringLiteral(init.expression.arguments[0]) ? init : null;
      if (req && ts.isIdentifier(node.name)) table.set(node.name.text, { mod: normModule(req), member: null, spec: req });
      if (req && ts.isObjectBindingPattern(node.name)) {
        for (const el of node.name.elements) {
          if (ts.isIdentifier(el.name)) table.set(el.name.text, { mod: normModule(req), member: el.propertyName ? el.propertyName.getText(sf) : el.name.text, spec: req });
        }
      }
      if (reqMember && ts.isIdentifier(node.name)) {
        const spec = reqMember.expression.arguments[0].text;
        table.set(node.name.text, { mod: normModule(spec), member: reqMember.name.text, spec });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  // promisify(exec) / util.promisify(cp.exec): the wrapper is the sink.
  const visit2 = node => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const init = unwrap(node.initializer);
      if (init && ts.isCallExpression(init) && /(^|\.)promisify$/.test(init.expression.getText(sf)) && init.arguments[0]) {
        const target = resolveCallee(init.arguments[0], table, sf);
        if (target && target.mod) table.set(node.name.text, { mod: target.mod, member: target.member, spec: target.mod });
      }
    }
    ts.forEachChild(node, visit2);
  };
  visit2(sf);
  return table;
}

/** What a call expression's callee refers to: { mod, member } | { global } | { method, receiver }. */
function resolveCallee(expr, imports, sf) {
  expr = unwrap(expr);
  if (!expr) return null;
  if (ts.isIdentifier(expr)) {
    const imp = imports.get(expr.text);
    // An import from the server's own code ('./x') is a function to follow, not a library.
    if (imp && imp.spec.startsWith('.')) return { global: imp.member || expr.text, spec: imp.spec };
    return imp ? { mod: imp.mod, member: imp.member, spec: imp.spec, local: expr.text } : { global: expr.text };
  }
  if (ts.isPropertyAccessExpression(expr)) {
    const name = expr.name.text;
    // fs.promises.readFile, cp.exec, axios.get
    let base = unwrap(expr.expression);
    if (ts.isPropertyAccessExpression(base) && base.name.text === 'promises') base = unwrap(base.expression);
    if (ts.isIdentifier(base)) {
      const imp = imports.get(base.text);
      if (imp && imp.spec.startsWith('.')) return { global: name, spec: imp.spec }; // import * as logic from './logic'
      if (imp && imp.member === null) return { mod: imp.mod, member: name };
      if (imp && imp.member) return { mod: imp.mod, member: `${imp.member}.${name}` };
      if (['path', 'JSON', 'Buffer', 'Array', 'Object', 'url'].includes(base.text)) return { global: `${base.text}.${name}` };
    }
    return { method: name, receiver: expr.expression };
  }
  return null;
}

function stringLiteral(node) {
  node = unwrap(node);
  return node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : null;
}

function objectProp(node, name) {
  node = unwrap(node);
  if (!node || !ts.isObjectLiteralExpression(node)) return undefined;
  for (const p of node.properties) {
    if (ts.isPropertyAssignment(p) && p.name && p.name.getText() === name) return p.initializer;
    if (ts.isShorthandPropertyAssignment(p) && p.name.text === name) return p.name;
  }
  return undefined;
}

/**
 * Sink spec for a call: { category, args: [expr…], kind } or null.
 * kind: 'start' (URL must start tainted), 'built' (SQL must be built from taint).
 */
function sinkFor(call, target, sf) {
  if (!target) return null;
  const a = call.arguments;
  const isNew = ts.isNewExpression(call);
  if (target.mod === 'child_process') {
    const m = target.member;
    if (m === 'exec' || m === 'execSync') return { category: 'shell', name: `child_process.${m}`, args: [a[0]] };
    if (['spawn', 'spawnSync', 'execFile', 'execFileSync'].includes(m)) {
      const opts = [...(a || [])].find(x => unwrap(x) && ts.isObjectLiteralExpression(unwrap(x)));
      const shell = opts && objectProp(opts, 'shell');
      const shellOn = shell && !(unwrap(shell).kind === ts.SyntaxKind.FalseKeyword);
      const cmd = stringLiteral(a[0]);
      const argv = a[1] && unwrap(a[1]) && ts.isArrayLiteralExpression(unwrap(a[1])) ? unwrap(a[1]).elements : null;
      const dashC = cmd && SHELLS.has(cmd) && argv && argv.some(e => ['-c', '/c', '-Command'].includes(stringLiteral(e)));
      if (shellOn) return { category: 'shell', name: `child_process.${m} (shell: true)`, args: [a[0], ...(argv || [a[1]])] };
      if (dashC) return { category: 'shell', name: `child_process.${m} (${cmd} -c)`, args: argv };
    }
    return null;
  }
  if (target.mod === 'execa' && /^execaCommand(Sync)?$/.test(target.member || '')) return { category: 'shell', name: `execa.${target.member}`, args: [a[0]] };
  if (target.global === 'eval') return { category: 'exec', name: 'eval', args: [a[0]] };
  if (isNew && target.global === 'Function') return { category: 'exec', name: 'new Function', args: [...(a || [])] };
  if (target.mod === 'vm' && /^(runIn(New|This)?Context|compileFunction|Script)$/.test(target.member || '')) return { category: 'exec', name: `vm.${target.member}`, args: [a && a[0]] };
  if (target.mod === 'fs' && target.member && FS_PATH_FNS.has(target.member.split('.').pop())) {
    const fn = target.member.split('.').pop();
    return { category: 'file', name: `fs.${fn}`, args: FS_TWO_PATHS.has(fn) ? [a[0], a[1]] : [a[0]] };
  }
  const urlArg = () => {
    const first = a && a[0];
    const viaObj = first && objectProp(first, 'url');
    return viaObj !== undefined ? viaObj : first;
  };
  if (target.global === 'fetch' || (target.mod === 'fetch')) return { category: 'network', name: 'fetch', args: [urlArg()], kind: 'start' };
  if (target.mod === 'axios' && (target.member === null || HTTP_METHODS.has(target.member))) return { category: 'network', name: `axios${target.member ? '.' + target.member : ''}`, args: [urlArg()], kind: 'start' };
  if (target.mod === 'got' && (target.member === null || HTTP_METHODS.has(target.member))) return { category: 'network', name: 'got', args: [urlArg()], kind: 'start' };
  if (target.mod === 'http' && ['request', 'get'].includes(target.member)) return { category: 'network', name: `http.${target.member}`, args: [urlArg()], kind: 'start' };
  if (target.method && SQL_METHODS.has(target.method) && a && a[0]) return { category: 'sql', name: `.${target.method}()`, args: [a[0]], kind: 'built' };
  return null;
}

// ── function index (for inter-procedural calls) ───────────────────────────

function fnName(node) {
  if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name) return node.name.getText();
  const p = node.parent;
  if (p && ts.isVariableDeclaration(p) && ts.isIdentifier(p.name)) return p.name.text;
  if (p && (ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p)) && p.name) return p.name.getText();
  return null;
}

function buildIndex(files) {
  const units = [];
  const byName = new Map();
  for (const f of files) {
    const sf = ts.createSourceFile(f.path, f.content, ts.ScriptTarget.Latest, true, scriptKind(f.path));
    const imports = importsOf(sf);
    const unit = { file: f.path, sf, imports };
    units.push(unit);
    const visit = node => {
      if (isFn(node)) {
        const name = fnName(node);
        if (name) {
          if (!byName.has(name)) byName.set(name, []);
          byName.get(name).push({ name, node, unit });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return { units, byName, byFile: new Map(units.map(u => [u.file, u])) };
}

function stem(p) {
  return p.replace(/\.(d\.)?(m|c)?(ts|tsx|js|jsx)$/, '').replace(/\/index$/, '');
}

/** Functions a call may enter: same file, then the relative module it was imported from, then a unique global name. */
function candidates(index, unit, target) {
  const name = target.global || target.local || target.method;
  if (!name) return [];
  const all = index.byName.get(name) || [];
  if (all.length === 0) return [];
  const same = all.filter(c => c.unit === unit);
  if (same.length) return same.slice(0, MAX_CANDIDATES);
  // obj.method(): the receiver's type is unknown, so a same-named function in
  // another file (client.run → a dev script's run()) is not evidence of a call.
  if (target.method) return [];
  if (target.spec && target.spec.startsWith('.')) {
    const dir = unit.file.includes('/') ? unit.file.slice(0, unit.file.lastIndexOf('/')) : '';
    const parts = (dir ? dir.split('/') : []).concat(target.spec.split('/'));
    const out = [];
    for (const p of parts) { if (p === '..') out.pop(); else if (p !== '.' && p !== '') out.push(p); }
    const want = stem(out.join('/'));
    const hit = all.filter(c => stem(c.unit.file) === want);
    if (hit.length) return hit.slice(0, MAX_CANDIDATES);
  }
  return all.length === 1 ? all : [];
}

// ── taint engine ──────────────────────────────────────────────────────────

const merge = (a, b) => (!a ? b : !b ? a : (a.hops <= b.hops ? { ...a, sanitized: a.sanitized && b.sanitized } : { ...b, sanitized: a.sanitized && b.sanitized }));
const extend = (info, step) => info && ({ ...info, hops: info.hops + 1, path: [...info.path, step].slice(0, 16) });

class Analysis {
  constructor(index) {
    this.index = index;
    this.findings = new Map();
    this.memo = new Map();
    this.stack = new Set();
    this.deadline = Date.now() + BUDGET_MS;
  }

  checkBudget() {
    if (Date.now() > this.deadline) throw new BudgetExceeded();
  }

  /** Analyze `fn` with tainted parameter positions; returns the taint of its return value. */
  run(entry, taints, depth, origin) {
    const key = `${entry.unit.file}:${entry.node.pos}:${taints.map(t => (t ? 1 : 0)).join('')}`;
    if (this.memo.has(key)) return this.memo.get(key);
    if (this.stack.has(key) || depth > MAX_DEPTH) return null;
    this.stack.add(key);
    const fa = new FnAnalysis(this, entry, depth, origin);
    entry.node.parameters.forEach((p, i) => { if (taints[i]) fa.bind(p.name, extend(taints[i], p.name.getText())); });
    const ret = fa.analyze();
    this.stack.delete(key);
    this.memo.set(key, ret);
    return ret;
  }
}

class FnAnalysis {
  constructor(analysis, entry, depth, origin) {
    this.a = analysis;
    this.entry = entry;
    this.unit = entry.unit;
    this.sf = entry.unit.sf;
    this.depth = depth;
    this.origin = origin;
    this.vars = new Map();
    this.built = new Set();  // variables holding a string built from taint (template / +)
    this.ret = null;
    this.recording = false;
    this.version = 0;          // bumped whenever a variable's taint changes
    this.cache = new Map();    // expression node -> { version, value }
  }

  setVar(name, info) {
    const prev = this.vars.get(name);
    const next = merge(prev, info);
    if (prev && next.hops === prev.hops && next.sanitized === prev.sanitized && next.origin === prev.origin) return;
    this.vars.set(name, next);
    this.version++;
  }

  bind(nameNode, info) {
    if (!nameNode || !info) return;
    if (ts.isIdentifier(nameNode)) { this.setVar(nameNode.text, info); return; }
    if (ts.isObjectBindingPattern(nameNode) || ts.isArrayBindingPattern(nameNode)) {
      for (const el of nameNode.elements) if (ts.isBindingElement(el)) this.bind(el.name, extend(info, el.name.getText()));
    }
  }

  analyze() {
    const body = this.entry.node.body;
    if (!body) return null;
    this.walk(body);            // pass 1: settle variables assigned later (loops)
    this.recording = true;
    this.walk(body);            // pass 2: record sinks
    return this.ret;
  }

  walk(node) {
    if (!node) return;
    this.a.checkBudget();
    if (ts.isVariableDeclaration(node)) {
      if (node.initializer) {
        this.walk(node.initializer);
        const t = this.taint(node.initializer);
        this.bind(node.name, t);
        if (ts.isIdentifier(node.name) && this.isBuilt(node.initializer) && !this.built.has(node.name.text)) {
          this.built.add(node.name.text);
          this.version++;
        }
      }
      return;
    }
    if (ts.isBinaryExpression(node) && [ts.SyntaxKind.EqualsToken, ts.SyntaxKind.PlusEqualsToken].includes(node.operatorToken.kind)) {
      this.walk(node.right);
      const t = this.taint(node.right);
      let lhs = unwrap(node.left);
      if (t) {
        while (lhs && (ts.isPropertyAccessExpression(lhs) || ts.isElementAccessExpression(lhs))) lhs = unwrap(lhs.expression);
        if (lhs && ts.isIdentifier(lhs)) this.setVar(lhs.text, extend(t, lhs.text));
        if (lhs && ts.isIdentifier(lhs) && (this.isBuilt(node.right) || node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken) && !this.built.has(lhs.text)) {
          this.built.add(lhs.text);
          this.version++;
        }
      }
      return;
    }
    if (ts.isReturnStatement(node) && node.expression) {
      this.walk(node.expression);
      this.ret = merge(this.ret, this.taint(node.expression));
      return;
    }
    if (isFn(node) && node !== this.entry.node) {
      // A nested function sees the enclosing variables (closure). Callbacks of
      // array methods on a tainted value receive tainted elements.
      const p = node.parent;
      if (p && ts.isCallExpression(p) && ts.isPropertyAccessExpression(p.expression) && ITERATOR_METHODS.has(p.expression.name.text)) {
        const t = this.taint(p.expression.expression);
        if (t && node.parameters[0]) this.bind(node.parameters[0].name, extend(t, node.parameters[0].name.getText()));
      }
      if (node.body) this.walk(node.body);
      return;
    }
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      ts.forEachChild(node, c => this.walk(c));
      this.callEffects(node);
      return;
    }
    ts.forEachChild(node, c => this.walk(c));
  }

  /** A validator called on a variable (statement or condition) sanitizes it from here on. */
  applyGuard(call, target) {
    const name = target && (target.global || target.member || target.method);
    if (!name || !GUARD_RE.test(String(name).split('.').pop())) return;
    for (const arg of call.arguments || []) {
      let base = unwrap(arg);
      while (base && (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base))) base = unwrap(base.expression);
      if (base && ts.isIdentifier(base)) {
        const t = this.vars.get(base.text);
        if (t && !t.sanitized) { this.vars.set(base.text, { ...t, sanitized: true }); this.version++; }
      }
    }
  }

  /** Sink check and mutation effects of a call (taint of its value comes from taint()). */
  callEffects(call) {
    const target = resolveCallee(call.expression, this.unit.imports, this.sf);
    this.applyGuard(call, target);
    const sink = sinkFor(call, target, this.sf);
    if (sink && this.recording) {
      for (const arg of sink.args) {
        if (!arg) continue;
        const t = this.taint(arg);
        if (!t) continue;
        let severity;
        let note = '';
        if (t.sanitized) severity = 'low';
        else if (sink.category === 'shell' || sink.category === 'exec') severity = 'high';
        else severity = 'medium';
        if (sink.kind === 'start' && !this.startsTainted(arg)) continue; // tool input only in path/query of a fixed host
        if (sink.kind === 'built' && !this.isBuilt(arg)) {
          if (sink.name === '.exec()') continue; // RegExp#exec(input) is not SQL
          severity = 'low';
          note = ' (whole query from tool input: runs queries by design)';
        }
        if (sink.kind === 'start' && severity === 'medium' && this.isBare(arg)) note = ' (the whole URL is tool input)';
        this.record(call, sink, t, severity, note);
      }
    }
    // arr.push(tainted) / obj.set(k, tainted) taint the receiver
    if (target && target.method && ['push', 'unshift', 'set', 'add', 'append', 'concat'].includes(target.method)) {
      const t = (call.arguments || []).map(x => this.taint(x)).reduce(merge, null);
      let r = unwrap(target.receiver);
      while (r && (ts.isPropertyAccessExpression(r) || ts.isElementAccessExpression(r))) r = unwrap(r.expression);
      if (t && r && ts.isIdentifier(r)) this.setVar(r.text, t);
    }
  }

  record(call, sink, t, severity, note) {
    const [threat, cwe] = THREAT[sink.category];
    let fn = call.parent;
    while (fn && !isFn(fn)) fn = fn.parent;
    const fnNode = fn || this.entry.node;
    const span = { name: fnName(fnNode) || '(anonymous)', start_line: lineOf(this.sf, fnNode.getStart(this.sf)), end_line: lineOf(this.sf, fnNode.end) };
    const line = lineOf(this.sf, call.getStart(this.sf));
    const fid = canonicalDigest([ID, this.unit.file, line, call.getStart(this.sf), sink.name, threat]);
    const prev = this.a.findings.get(fid);
    if (prev && SEVERITY_SCORE[prev.severity] >= SEVERITY_SCORE[severity]) return;
    this.a.findings.set(fid, {
      finding_id: fid, threat, cwe, score: SEVERITY_SCORE[severity], severity,
      location: { file: this.unit.file, line, function: span, tool_id: null },
      summary: `tool input reaches ${sink.name} in ${span.name}()${note}: ${t.path.join(' → ')}`,
      details: { sink: sink.name, category: sink.category, entry: this.origin, path: t.path, hops: t.hops, sanitized: !!t.sanitized,
        code: (this.sf.text.split('\n')[line - 1] || '').trim().slice(0, 200) },
    });
  }

  isBare(expr) {
    expr = unwrap(expr);
    return !!expr && (ts.isIdentifier(expr) || ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) && !(ts.isIdentifier(expr) && this.built.has(expr.text));
  }

  /** A string built from tool input around constant text: template literal or `+` with a literal side. */
  isBuilt(expr) {
    expr = unwrap(expr);
    if (!expr) return false;
    if (ts.isIdentifier(expr)) return this.built.has(expr.text);
    if (ts.isTemplateExpression(expr)) {
      const constText = expr.head.text + expr.templateSpans.map(s => s.literal.text).join('');
      return constText.trim().length > 0 && expr.templateSpans.some(s => this.taint(s.expression));
    }
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const lit = n => !!stringLiteral(n) || (unwrap(n) && ts.isTemplateExpression(unwrap(n)));
      return (lit(expr.left) || lit(expr.right) || this.isBuilt(expr.left) || this.isBuilt(expr.right)) && !!this.taint(expr);
    }
    if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression) && ['replace', 'concat', 'join'].includes(expr.expression.name.text)) {
      return !!this.taint(expr) && (this.isBuilt(expr.expression.expression) || !!stringLiteral(expr.expression.expression));
    }
    return false;
  }

  /** Taint of what a callback returns (expression body, or its own return statements). */
  returnTaint(fn, g) {
    if (!fn.body) return null;
    if (!ts.isBlock(fn.body)) return this.taint(fn.body, g);
    let t = null;
    const visit = n => {
      if (isFn(n)) return; // nested functions return for themselves
      if (ts.isReturnStatement(n) && n.expression) t = merge(t, this.taint(n.expression, g));
      ts.forEachChild(n, visit);
    };
    ts.forEachChild(fn.body, visit);
    return t;
  }

  /** Does the value START with tool input (so the attacker picks scheme/host)? */
  startsTainted(expr) {
    expr = unwrap(expr);
    if (!expr) return false;
    if (ts.isTemplateExpression(expr)) return expr.head.text.trim() === '' && !!this.taint(expr.templateSpans[0].expression);
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) return this.startsTainted(expr.left);
    if (ts.isNewExpression(expr) && ts.isIdentifier(expr.expression) && expr.expression.text === 'URL') {
      const args = expr.arguments || [];
      return args.length >= 2 ? this.startsTainted(args[1]) : this.startsTainted(args[0]);
    }
    if (stringLiteral(expr) !== null) return false;
    return !!this.taint(expr);
  }

  taint(expr, guard = 0) {
    expr = unwrap(expr);
    if (!expr || guard > 60) return null;
    const hit = this.cache.get(expr);
    if (hit && hit.version === this.version) return hit.value;
    const value = this.taintUncached(expr, guard);
    this.cache.set(expr, { version: this.version, value });
    return value;
  }

  taintUncached(expr, guard) {
    const g = guard + 1;
    if (ts.isIdentifier(expr)) return this.vars.get(expr.text) || null;
    if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) return this.taint(expr.expression, g);
    if (ts.isTemplateExpression(expr)) return expr.templateSpans.map(s => this.taint(s.expression, g)).reduce(merge, null);
    if (ts.isBinaryExpression(expr)) {
      const k = expr.operatorToken.kind;
      if ([ts.SyntaxKind.PlusToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.CommaToken].includes(k)) {
        return merge(this.taint(expr.left, g), this.taint(expr.right, g));
      }
      return null; // comparisons, arithmetic: a boolean/number is not an injection vector
    }
    if (ts.isConditionalExpression(expr)) return merge(this.taint(expr.whenTrue, g), this.taint(expr.whenFalse, g));
    if (ts.isArrayLiteralExpression(expr)) return expr.elements.map(e => this.taint(ts.isSpreadElement(e) ? e.expression : e, g)).reduce(merge, null);
    if (ts.isObjectLiteralExpression(expr)) {
      return expr.properties.map(p => (ts.isPropertyAssignment(p) ? this.taint(p.initializer, g)
        : ts.isShorthandPropertyAssignment(p) ? this.taint(p.name, g)
          : ts.isSpreadAssignment(p) ? this.taint(p.expression, g) : null)).reduce(merge, null);
    }
    if (ts.isSpreadElement(expr)) return this.taint(expr.expression, g);
    if (ts.isCallExpression(expr) || ts.isNewExpression(expr)) return this.callTaint(expr, g);
    return null;
  }

  callTaint(call, g) {
    const args = (call.arguments || []).map(a => this.taint(a, g));
    const argTaint = args.reduce(merge, null);
    const target = resolveCallee(call.expression, this.unit.imports, this.sf);
    if (!target) return null;
    const full = target.global || (target.mod ? `${target.mod}.${target.member}` : null);
    const bare = target.global || target.member || target.method || '';
    if (full && SANITIZER_FULL.has(full)) return argTaint && { ...argTaint, sanitized: true };
    if (bare && SANITIZER_RE.test(bare.split('.').pop())) {
      const recv = target.receiver ? this.taint(target.receiver, g) : null;
      const t = merge(argTaint, recv);
      return t && { ...t, sanitized: true };
    }
    if (full && (PROPAGATING_GLOBALS.has(full) || (target.mod === 'path' && target.member !== 'basename'))) return argTaint;
    // arr.map(cb) / arr.flatMap(cb): the result carries what cb RETURNS, so
    // `ids.map(() => '?').join(',')` (placeholders for a parameterised query) is clean.
    if (target.method && ['map', 'flatMap'].includes(target.method) && call.arguments[0] && isFn(unwrap(call.arguments[0]))) {
      const cb = unwrap(call.arguments[0]);
      const recv = this.taint(target.receiver, g);
      if (recv && cb.parameters[0]) this.bind(cb.parameters[0].name, extend(recv, cb.parameters[0].name.getText()));
      return this.returnTaint(cb, g);
    }
    if (target.method && STRING_METHODS.has(target.method)) return merge(this.taint(target.receiver, g), argTaint);
    if (target.mod) return target.mod === 'child_process' || target.mod === 'fs' ? argTaint : null;
    // The server's own functions: follow the call when tool input is passed in.
    if (argTaint && this.depth < MAX_DEPTH) {
      let ret = null;
      for (const c of candidates(this.a.index, this.unit, target)) {
        if (c.node === this.entry.node) continue;
        ret = merge(ret, this.a.run(c, args.map(t => t && extend(t, `${c.name}()`)), this.depth + 1, this.origin));
      }
      if (ret) return ret;
    }
    if (target.method) return this.taint(target.receiver, g); // unknown method on a tainted object
    return null;
  }
}

// ── entry points ──────────────────────────────────────────────────────────

/** Top-level functions inside a tool's handler span: the tool handler(s). */
function entriesForTool(unit, tool) {
  const out = [];
  const { start_line: lo, end_line: hi } = tool.handler;
  const visit = (node, inside) => {
    if (isFn(node) && node.body) {
      const s = lineOf(unit.sf, node.getStart(unit.sf));
      const e = lineOf(unit.sf, node.end);
      if (s >= lo && e <= hi && !inside && !(ts.isMethodDeclaration(node) && NOT_A_SOURCE_METHOD.has(fnName(node)))) {
        out.push({ name: fnName(node) || tool.name, node, unit });
        inside = true;
      }
    }
    ts.forEachChild(node, c => visit(c, inside));
  };
  visit(unit.sf, false);
  return out;
}

/** setRequestHandler(CallToolRequestSchema, (request) => …): the dispatch is a tool entry. */
function callToolDispatchers(unit) {
  const out = [];
  const visit = node => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)
      && node.expression.name.text === 'setRequestHandler' && node.arguments.length >= 2
      && /CallTool/.test(node.arguments[0].getText(unit.sf))) {
      const fn = unwrap(node.arguments[1]);
      if (fn && isFn(fn)) out.push({ name: 'CallToolRequest', node: fn, unit });
    }
    ts.forEachChild(node, visit);
  };
  visit(unit.sf);
  return out;
}

function identity() {
  return { id: ID, version: VERSION, artifact_hash: ARTIFACT_HASH, engine: 'static' };
}

function health() {
  return {
    ...identity(),
    display_name: 'TS/JS taint analyzer',
    description: 'Static, inter-procedural taint analysis for TypeScript/JavaScript MCP servers: does tool input reach a dangerous call?',
    consumes: ['files', 'tools'],
    languages: ['typescript', 'javascript'],
    threats: ['command_injection', 'code_injection', 'path_traversal', 'ssrf', 'sql_injection'],
    contract_version: '1',
  };
}

function analyze(bundle) {
  const files = bundle.files.filter(f => f.language === 'typescript' || f.language === 'javascript');
  if (files.length === 0) {
    return { analyzer: identity(), status: 'not_applicable', coverage: { units_total: 0, units_analyzed: 0, languages: [], notes: ['no TypeScript/JavaScript source in bundle'] }, findings: [] };
  }
  const index = buildIndex(files);
  const analysis = new Analysis(index);
  const entries = [];
  for (const tool of bundle.tools) {
    const unit = index.byFile.get(tool.file);
    if (unit) for (const e of entriesForTool(unit, tool)) entries.push({ ...e, origin: tool.name });
  }
  for (const unit of index.units) for (const e of callToolDispatchers(unit)) entries.push({ ...e, origin: e.name });
  const seen = new Set();
  let partial = false;
  try {
    for (const e of entries) {
      const k = `${e.unit.file}:${e.node.pos}`;
      if (seen.has(k)) continue;
      seen.add(k);
      const taints = e.node.parameters.map(p => ({ origin: e.origin, hops: 0, path: [`${e.origin}(${p.name.getText().slice(0, 40)})`], sanitized: false }));
      analysis.run(e, taints, 0, e.origin);
    }
  } catch (err) {
    if (!(err instanceof BudgetExceeded)) throw err;
    partial = true;
  }
  const findings = [...analysis.findings.values()].map(f => {
    const tool = bundle.tools.find(t => t.file === f.location.file && t.handler.start_line <= f.location.function.end_line && f.location.function.start_line <= t.handler.end_line);
    return { ...f, location: { ...f.location, tool_id: tool ? tool.tool_id : null } };
  });
  findings.sort((x, y) => (x.location.file < y.location.file ? -1 : x.location.file > y.location.file ? 1 : x.location.line - y.location.line || (x.finding_id < y.finding_id ? -1 : 1)));
  const notes = entries.length ? [] : ['no tool handler entry points found in TS/JS code'];
  if (partial) notes.push(`time budget (${BUDGET_MS} ms) exceeded after ${seen.size}/${entries.length} tool entry points; findings so far are reported`);
  return {
    analyzer: identity(), status: partial ? 'partial' : 'ok',
    coverage: { units_total: files.length, units_analyzed: files.length, languages: ['typescript', 'javascript'], notes },
    findings,
  };
}

module.exports = { id: ID, health, analyze };
