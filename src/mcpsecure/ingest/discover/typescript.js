/**
 * MCP Secure — static tool discovery for TypeScript / JavaScript servers
 * =======================================================================
 * Parses with the real TypeScript compiler (never executes) and recognises:
 *
 *   server.tool(name, [description], [zodShape], handler)          high-level SDK
 *   server.registerTool(name, { title, description, inputSchema }, handler)
 *   server.setRequestHandler(ListToolsRequestSchema, …)             low-level SDK
 *     → tool literals { name, description, inputSchema } in the handler,
 *       dispatched by setRequestHandler(CallToolRequestSchema, …)
 *   tool definitions anywhere in an MCP SDK repo, registered later through a
 *   variable, an array or a loop:
 *     export const X = { name, description, inputSchema | parameters | … }
 *     export const defs = { list_buckets: { description, parameters } }
 *     class FindTool extends ToolBase { static toolName = "find"; description = … }
 *
 * Names and descriptions resolve through string constants and object
 * properties across files: `registerTool(getDataTool.name, …)`,
 * `description: DESCRIPTIONS.search`, `${PREFIX}_search`.
 *
 * The handler span is the whole registration call, which is also the unit
 * Model B's extractor scores for callback-style tools — so spans overlap and
 * findings from both sides can be matched to the same tool.
 */

const ts = require('typescript');

function scriptKind(file) {
  if (/\.tsx$/.test(file)) return ts.ScriptKind.TSX;
  if (/\.(m|c)?ts$/.test(file)) return ts.ScriptKind.TS;
  if (/\.jsx$/.test(file)) return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

function lineOf(sf, pos) {
  return sf.getLineAndCharacterOfPosition(pos).line + 1;
}

function unwrap(node) {
  while (node && (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node)
    || ts.isTypeAssertionExpression(node) || (ts.isSatisfiesExpression && ts.isSatisfiesExpression(node)))) {
    node = node.expression;
  }
  return node;
}

/** Top-level `const X = …` (exported or not) per file: name → initializer. */
function collectDeclarations(sf) {
  const decls = new Map();
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) continue;
    for (const decl of stmt.declarationList.declarations) {
      if (ts.isIdentifier(decl.name) && decl.initializer) decls.set(decl.name.text, unwrap(decl.initializer));
    }
  }
  return decls;
}

/**
 * Resolves strings and object literals statically. Lookup order for an
 * identifier: the file's own top-level constants, then a constant of that name
 * declared exactly once anywhere else in the repository (an import, in effect).
 */
function makeResolver(local, global) {
  const active = new Set();
  const lookup = name => {
    if (local.has(name)) return local.get(name);
    const g = global.get(name);
    return g && g.length === 1 ? g[0] : null;
  };
  const obj = node => {
    node = unwrap(node);
    if (!node) return null;
    if (ts.isObjectLiteralExpression(node)) return node;
    if (ts.isIdentifier(node)) {
      if (active.has(node.text)) return null;
      active.add(node.text);
      try { return obj(lookup(node.text)); } finally { active.delete(node.text); }
    }
    if (ts.isPropertyAccessExpression(node)) return obj(objectPropRaw(obj(node.expression), node.name.text));
    return null;
  };
  const str = node => {
    node = unwrap(node);
    if (!node) return null;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
    if (ts.isIdentifier(node)) {
      if (active.has(node.text)) return null;
      active.add(node.text);
      try { return str(lookup(node.text)); } finally { active.delete(node.text); }
    }
    if (ts.isPropertyAccessExpression(node)) return str(objectPropRaw(obj(node.expression), node.name.text));
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const l = str(node.left);
      const r = l === null ? null : str(node.right);
      return l !== null && r !== null ? l + r : null;
    }
    if (ts.isTemplateExpression(node)) {
      let out = node.head.text;
      for (const span of node.templateSpans) {
        const v = str(span.expression);
        if (v === null) return null;
        out += v + span.literal.text;
      }
      return out;
    }
    return null;
  };
  return { str, obj };
}

function literalString(node, ctx) {
  return ctx.str(node);
}

function propName(p) {
  if (!p.name) return null;
  if (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name) || ts.isNoSubstitutionTemplateLiteral(p.name)) return p.name.text;
  return null;
}

function objectPropRaw(obj, name) {
  if (!obj || !ts.isObjectLiteralExpression(obj)) return null;
  const p = obj.properties.find(q => (ts.isPropertyAssignment(q) || ts.isShorthandPropertyAssignment(q)) && propName(q) === name);
  if (!p) return null;
  return ts.isShorthandPropertyAssignment(p) ? p.name : p.initializer;
}

function objectProp(obj, name) {
  return objectPropRaw(obj, name);
}

const ZOD_TYPES = { string: 'string', number: 'number', boolean: 'boolean', array: 'array', object: 'object', enum: 'string', bigint: 'integer' };

/** `z.string().describe("…").optional()` → { type, description }, optional. */
function zodField(expr, ctx) {
  const out = {};
  let optional = false;
  let node = expr;
  while (node && ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const method = node.expression.name.text;
    if (method === 'describe' && node.arguments[0]) {
      const d = literalString(node.arguments[0], ctx);
      if (d !== null && out.description === undefined) out.description = d;
    } else if (method === 'optional' || method === 'nullish' || method === 'default') {
      optional = true;
    } else if (method === 'int') {
      out.type = 'integer';
    } else if (ZOD_TYPES[method] && ts.isIdentifier(node.expression.expression)) {
      if (!out.type) out.type = ZOD_TYPES[method];
    }
    node = node.expression.expression;
  }
  return { schema: out, optional };
}

/** A zod raw shape `{ a: z.string(), … }` or a JSON-schema literal → JSON schema. */
function shapeToSchema(node, ctx) {
  node = unwrap(node);
  // z.object({ … }) / z.object({ … }).strict() → its shape
  while (node && ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    if (node.expression.name.text === 'object' && node.arguments[0]) { node = unwrap(node.arguments[0]); break; }
    node = node.expression.expression;
  }
  if (node && !ts.isObjectLiteralExpression(node)) node = ctx.obj(node);
  if (!node || !ts.isObjectLiteralExpression(node)) return { type: 'object', properties: {} };
  // Already a JSON schema literal?
  if (objectProp(node, 'type') && objectProp(node, 'properties')) {
    return jsonLiteral(node) || { type: 'object', properties: {} };
  }
  const properties = {};
  const required = [];
  for (const p of node.properties) {
    if (!ts.isPropertyAssignment(p)) continue;
    const name = propName(p);
    if (!name) continue;
    const { schema, optional } = zodField(p.initializer, ctx);
    properties[name] = schema;
    if (!optional) required.push(name);
  }
  const schema = { type: 'object', properties };
  if (required.length) schema.required = required;
  return schema;
}

/** Literal-only object/array → plain JS value, else null. */
function jsonLiteral(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (node.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isArrayLiteralExpression(node)) {
    const out = node.elements.map(jsonLiteral);
    return out.some(v => v === undefined) ? undefined : out;
  }
  if (ts.isObjectLiteralExpression(node)) {
    const out = {};
    for (const p of node.properties) {
      if (!ts.isPropertyAssignment(p) || !propName(p)) return undefined;
      const v = jsonLiteral(p.initializer);
      if (v === undefined) return undefined;
      out[propName(p)] = v;
    }
    return out;
  }
  return undefined;
}

function isFunctionLike(n) {
  return n && (ts.isArrowFunction(n) || ts.isFunctionExpression(n) || ts.isIdentifier(n));
}

function calleeName(call) {
  const e = call.expression;
  if (ts.isPropertyAccessExpression(e)) return e.name.text;
  if (ts.isIdentifier(e)) return e.text;
  return null;
}

// Keys that mark an object literal as an MCP tool definition (with `name` and `description`).
const DEFINITION_SCHEMA_KEYS = ['inputSchema', 'input_schema', 'parameters', 'parametersSchema', 'argsSchema', 'zodSchema'];
const MCP_SDK_RE = /@modelcontextprotocol\/|\bfastmcp\b|mcp[-_](framework|utils|server|sdk)\b|McpServer\b/i;

function discoverFile(file, global, scanDefinitions) {
  const sf = file.sf;
  const ctx = makeResolver(file.decls, global);
  const tools = [];
  let listToolsCall = null;
  let callToolCall = null;
  const claimed = new Set(); // object literals already reported through a registration call

  const span = node => ({ start_line: lineOf(sf, node.getStart(sf)), end_line: lineOf(sf, node.getEnd()) });
  const describe = node => {
    if (!node) return { description: '', resolved: true };
    const d = ctx.str(node);
    return { description: d || '', resolved: d !== null };
  };

  const visit = node => {
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      const args = node.arguments;
      const registration = (name === 'registerTool' && args.length >= 2)
        || (name === 'tool' && args.length >= 2 && isFunctionLike(args[args.length - 1]));
      if (registration) {
        const toolName = ctx.str(args[0]);
        if (toolName) {
          let desc = { description: '', resolved: true };
          let schema = { type: 'object', properties: {} };
          if (name === 'registerTool') {
            const cfg = ctx.obj(args[1]);
            if (cfg) {
              claimed.add(cfg);
              desc = describe(objectProp(cfg, 'description'));
              schema = shapeToSchema(objectProp(cfg, 'inputSchema'), ctx);
            }
          } else {
            const middle = args.slice(1, -1);
            const descArg = middle.find(a => !ts.isObjectLiteralExpression(unwrap(a)) && !/shape$/i.test(a.getText(sf)));
            if (descArg) desc = describe(descArg);
            const shape = middle.find(a => a !== descArg);
            if (shape) schema = shapeToSchema(shape, ctx);
          }
          tools.push({
            name: toolName,
            description: desc.description,
            description_resolved: desc.resolved,
            input_schema: schema,
            handler: { name: toolName, ...span(node) },
            discovered_by: `ts:${name}`,
          });
        }
      } else if (name === 'setRequestHandler' && args[0] && ts.isIdentifier(args[0])) {
        if (args[0].text === 'ListToolsRequestSchema') listToolsCall = node;
        if (args[0].text === 'CallToolRequestSchema') callToolCall = node;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);

  // `{ list_buckets: { description, parameters } }`: the property key names the tool.
  const keyName = node => (node.parent && ts.isPropertyAssignment(node.parent) && node.parent.initializer === node
    ? propName(node.parent) : null);
  const schemaOf = node => {
    const key = DEFINITION_SCHEMA_KEYS.find(k => objectProp(node, k));
    const v = key ? unwrap(objectProp(node, key)) : null;
    // CLI command definitions use `parameters: ["[url]"]`; a tool schema is never an array or string.
    return v && !ts.isArrayLiteralExpression(v) && !ts.isStringLiteral(v) ? v : null;
  };

  const definition = (node, discoveredBy, handlerNode) => {
    const nameNode = objectProp(node, 'name');
    const n = nameNode ? ctx.str(nameNode) : discoveredBy === 'ts:tool_definition' ? keyName(node) : null;
    if (!n) return false;
    const schemaNode = schemaOf(node);
    if (discoveredBy === 'ts:tool_definition' && !schemaNode) return false;
    // A key-named entry needs a real schema (zod / variable / JSON Schema), not a map of parameter docs.
    if (!nameNode && !(ts.isIdentifier(schemaNode) || ts.isPropertyAccessExpression(schemaNode) || ts.isCallExpression(schemaNode)
        || (ts.isObjectLiteralExpression(schemaNode) && objectProp(schemaNode, 'type') && objectProp(schemaNode, 'properties')))) return false;
    const desc = describe(objectProp(node, 'description'));
    const literal = schemaNode && jsonLiteral(unwrap(schemaNode));
    tools.push({
      name: n,
      description: desc.description,
      description_resolved: desc.resolved,
      input_schema: (literal && typeof literal === 'object' && literal) || (schemaNode ? shapeToSchema(schemaNode, ctx) : { type: 'object', properties: {} }),
      handler: { name: n, ...span(handlerNode || node) },
      discovered_by: discoveredBy,
    });
    return true;
  };

  if (listToolsCall) {
    const handler = callToolCall || listToolsCall;
    const findLiterals = node => {
      if (ts.isObjectLiteralExpression(node) && objectProp(node, 'description') !== null && definition(node, 'ts:list_tools_literal', handler)) {
        claimed.add(node);
        return;
      }
      ts.forEachChild(node, findLiterals);
    };
    findLiterals(listToolsCall);
  }

  // class FindTool extends ToolBase { static toolName = "find"; description = "…" }
  const classTool = node => {
    const heritage = (node.heritageClauses || []).map(h => h.getText(sf)).join(' ');
    if (!/Tool\b/.test((node.name && node.name.text) || '') && !/Tool/.test(heritage)) return false;
    const member = names => node.members.find(m => ts.isPropertyDeclaration(m) && m.initializer && names.includes(propName(m)));
    const nameMember = member(['toolName', 'name']);
    const descMember = member(['description']);
    const n = nameMember && ctx.str(nameMember.initializer);
    if (!n || !descMember) return false;
    const desc = describe(descMember.initializer);
    const shapeMember = member(['argsShape', 'inputSchema', 'parameters']);
    tools.push({
      name: n,
      description: desc.description,
      description_resolved: desc.resolved,
      input_schema: shapeMember ? shapeToSchema(shapeMember.initializer, ctx) : { type: 'object', properties: {} },
      handler: { name: (node.name && node.name.text) || n, ...span(node) },
      discovered_by: 'ts:tool_class',
    });
    return true;
  };

  if (scanDefinitions) {
    const findDefinitions = node => {
      if (ts.isObjectLiteralExpression(node) && !claimed.has(node)
          && objectProp(node, 'description') !== null && definition(node, 'ts:tool_definition')) {
        return;
      }
      if (ts.isClassDeclaration(node) && classTool(node)) return;
      ts.forEachChild(node, findDefinitions);
    };
    findDefinitions(sf);
  }

  const notes = sf.parseDiagnostics && sf.parseDiagnostics.length
    ? [`${file.language} parse errors in ${file.path} (${sf.parseDiagnostics.length}); discovery may be incomplete`]
    : [];
  return { tools: tools.map(t => ({ ...t, file: file.path })), notes };
}

/**
 * One tool per name. A registration call wins over a bare definition object;
 * a definition fills in a description the registration could not resolve.
 */
function mergeByName(tools) {
  const rank = t => (t.discovered_by === 'ts:tool_definition' || t.discovered_by === 'ts:tool_class' ? 1 : 0);
  const byName = new Map();
  for (const t of tools) {
    const prev = byName.get(t.name);
    if (!prev) { byName.set(t.name, t); continue; }
    const [keep, other] = rank(t) < rank(prev) ? [t, prev] : [prev, t];
    if (!keep.description_resolved && other.description_resolved) {
      Object.assign(keep, { description: other.description, description_resolved: true });
    }
    byName.set(t.name, keep);
  }
  return [...byName.values()];
}

function discoverTypeScript(files) {
  const notes = [];
  const parsed = [];
  for (const f of files) {
    try {
      const sf = ts.createSourceFile(f.path, f.content, ts.ScriptTarget.Latest, true, scriptKind(f.path));
      parsed.push({ ...f, sf, decls: collectDeclarations(sf) });
    } catch (e) {
      notes.push(`ts discovery failed for ${f.path}: ${e.message}`);
    }
  }
  const global = new Map();
  for (const f of parsed) {
    for (const [name, init] of f.decls) {
      if (!global.has(name)) global.set(name, []);
      global.get(name).push(init);
    }
  }
  const scanDefinitions = files.some(f => MCP_SDK_RE.test(f.content));
  const tools = [];
  for (const f of parsed) {
    try {
      const r = discoverFile(f, global, scanDefinitions);
      tools.push(...r.tools);
      notes.push(...r.notes);
    } catch (e) {
      notes.push(`ts discovery failed for ${f.path}: ${e.message}`);
    }
  }
  return { tools: mergeByName(tools), notes };
}

module.exports = { discoverTypeScript };
