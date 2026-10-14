#!/usr/bin/env node
/**
 * Live rug-pull demo on the public testbed (needs push access to the repo).
 *
 *   node scripts/testbed.js rugpull   push the malicious weather server to `watcher-demo`
 *   node scripts/testbed.js reset     push the clean weather server back
 *   node scripts/testbed.js status    show which version `watcher-demo` holds
 *
 * Each action is a normal new commit (never a force push), exactly what a
 * publisher turning malicious would do. Then press "Poll Now" on /watcher.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const REPO = process.env.MCS_TESTBED_REPO || 'https://github.com/Talha-Qamar/mcp-secure-testbed';
const BRANCH = 'watcher-demo';
const SOURCE = { rugpull: 'rugpull-weather-py', reset: 'clean-weather-py' };
const action = process.argv[2];

if (!['rugpull', 'reset', 'status'].includes(action)) {
  console.error('usage: node scripts/testbed.js rugpull|reset|status');
  process.exit(2);
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcs-testbed-'));
const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
try {
  git('init', '-q');
  git('remote', 'add', 'origin', `${REPO}.git`);
  git('fetch', '-q', '--depth', '1', 'origin', BRANCH, SOURCE.rugpull, SOURCE.reset);
  const tree = ref => git('rev-parse', `origin/${ref}^{tree}`);
  const current = tree(BRANCH);
  const holds = current === tree(SOURCE.rugpull) ? 'malicious (rug pull)' : current === tree(SOURCE.reset) ? 'clean' : 'other';
  if (action === 'status') {
    console.log(`${BRANCH} @ ${git('rev-parse', '--short', `origin/${BRANCH}`)}: ${holds}`);
  } else {
    const target = tree(SOURCE[action]);
    if (target === current) {
      console.log(`${BRANCH} already holds the ${action === 'rugpull' ? 'malicious' : 'clean'} version; nothing to push`);
    } else {
      const msg = action === 'rugpull' ? 'Improve forecast accuracy' : 'Restore clean weather server';
      const commit = execFileSync('git', ['commit-tree', target, '-p', `origin/${BRANCH}`, '-m', msg], {
        cwd: dir, encoding: 'utf8',
        env: { ...process.env, GIT_AUTHOR_NAME: 'testbed', GIT_AUTHOR_EMAIL: 'testbed@users.noreply.github.com', GIT_COMMITTER_NAME: 'testbed', GIT_COMMITTER_EMAIL: 'testbed@users.noreply.github.com' },
      }).trim();
      git('push', '-q', 'origin', `${commit}:refs/heads/${BRANCH}`);
      console.log(`pushed ${commit.slice(0, 12)} to ${BRANCH} (${action === 'rugpull' ? 'malicious' : 'clean'}). Now press "Poll Now" on /watcher.`);
    }
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
