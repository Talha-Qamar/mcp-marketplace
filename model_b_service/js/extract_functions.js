#!/usr/bin/env node
// Usage: node extract_functions.js <file.ts|file.js>
// Reads source from argv[1] path, parses with the real TS compiler, emits JSON:
// [{ name, kind, text, startLine, endLine }, ...] for every function-like node
// (function declarations, const/let arrow functions, class methods).
const ts = require("typescript");
const fs = require("fs");

// v7: also supports batch mode to avoid one Node start-up per file:
//   node extract_functions.js --batch <file-with-one-path-per-line>
//   -> prints {"<path>": [functions...], ...}; unreadable/unparseable files map to [].
let src = "";
let sourceFile = null;
let results = [];

function loadFile(filePath) {
  src = fs.readFileSync(filePath, "utf8");
  const isTs = filePath.endsWith(".ts") || filePath.endsWith(".tsx");
  sourceFile = ts.createSourceFile(filePath, src, ts.ScriptTarget.Latest, true,
                                   isTs ? ts.ScriptKind.TS : ts.ScriptKind.JS);
  results = [];
}

function nameOf(node) {
  if (node.name) {
    if (ts.isIdentifier(node.name)) return node.name.text;
  }
  return null;
}

function visit(node, enclosingName) {
  let fnName = null;
  let fnNode = null;
  let kind = null;

  if (ts.isFunctionDeclaration(node) && node.body) {
    fnName = nameOf(node) || enclosingName;
    fnNode = node;
    kind = "function_declaration";
  } else if (ts.isMethodDeclaration(node) && node.body) {
    fnName = nameOf(node) || enclosingName;
    fnNode = node;
    kind = "method";
  } else if (ts.isVariableDeclaration(node) && node.initializer &&
             (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))) {
    fnName = ts.isIdentifier(node.name) ? node.name.text : enclosingName;
    fnNode = node; // capture the whole "const name = (...) => {...}" for context
    kind = "arrow_const";
  } else if (ts.isPropertyAssignment(node) && node.initializer &&
             (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)) &&
             ts.isBlock(node.initializer.body)) {
    // v7: object-literal tool definitions, e.g. { name: "x", execute: async (args) => {...} }
    const prop = (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) ? node.name.text : null;
    fnName = enclosingName && prop ? `${enclosingName}.${prop}` : (prop || enclosingName);
    fnNode = node;
    kind = "property_function";
  } else if ((ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && ts.isBlock(node.body) &&
             node.parent && ts.isCallExpression(node.parent) && node.parent.arguments.includes(node)) {
    // v7: handlers passed as callbacks. MCP servers register most tools this way:
    //   server.tool("name", schema, async (args) => {...})
    //   server.setRequestHandler(CallToolRequestSchema, async (request) => {...})
    // Emit the whole call (registration + schema + handler) when it is a tool/handler
    // registration, or any block-bodied callback at module level (not nested in a function,
    // to avoid re-emitting every .map(...) inside functions we already capture).
    const call = node.parent;
    const callee = call.expression;
    const calleeName = ts.isPropertyAccessExpression(callee) ? callee.name.text
                     : (ts.isIdentifier(callee) ? callee.text : null);
    const isRegistration = calleeName && /^(tool|registerTool|addTool|setRequestHandler|resource|registerResource|prompt|registerPrompt|handler|on|use|get|post|put|delete|command|action)$/.test(calleeName);
    if (isRegistration || !enclosingName) {
      const first = call.arguments[0];
      const label = first && (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) ? first.text
                  : (first && ts.isIdentifier(first) ? first.text : null);
      fnName = (label ? `${calleeName || "callback"}:${label}` : `${calleeName || "callback"}:callback`);
      fnNode = call;
      kind = "callback";
    }
  }

  if (fnNode && fnName) {
    const start = fnNode.getStart(sourceFile);
    const end = fnNode.getEnd();
    const text = src.slice(start, end);
    const startLine = sourceFile.getLineAndCharacterOfPosition(start).line + 1;
    const endLine = sourceFile.getLineAndCharacterOfPosition(end).line + 1;
    results.push({ name: fnName, kind, text, startLine, endLine });
  }

  ts.forEachChild(node, (child) => visit(child, fnName || enclosingName));
}

if (process.argv[2] === "--batch") {
  const paths = fs.readFileSync(process.argv[3], "utf8").split("\n").filter(Boolean);
  const out = {};
  for (const fp of paths) {
    try { loadFile(fp); visit(sourceFile, null); out[fp] = results; }
    catch (e) { out[fp] = []; }
  }
  process.stdout.write(JSON.stringify(out));
} else {
  try {
    loadFile(process.argv[2]);
    visit(sourceFile, null);
    console.log(JSON.stringify(results));
  } catch (e) {
    console.error("ERROR:", e.message);
    process.exit(1);
  }
}
