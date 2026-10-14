// Seeds a throwaway database, then starts the marketplace on E2E_PORT.
const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-e2e-'));
const env = { ...process.env, MCS_DB_PATH: path.join(dir, 'e2e.db'), SESSION_SECRET: 'e2e', PORT: process.env.E2E_PORT || '3100' };

execFileSync(process.execPath, [path.join(ROOT, 'database', 'seed.js')], { env, stdio: 'inherit' });
const server = spawn(process.execPath, [path.join(ROOT, 'server.js')], { cwd: ROOT, env, stdio: 'inherit' });
const stop = () => { server.kill(); fs.rmSync(dir, { recursive: true, force: true }); };
process.on('SIGTERM', () => { stop(); process.exit(0); });
process.on('SIGINT', () => { stop(); process.exit(0); });
server.on('exit', code => { fs.rmSync(dir, { recursive: true, force: true }); process.exit(code || 0); });
