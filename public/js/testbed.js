/**
 * MCP Secure — live testbed presets (demo mode)
 * ==============================================
 * Each case is a branch of the public testbed repository (intentionally
 * vulnerable fixtures from demo_servers/ and eval/adversarial/), scanned live
 * through normal git ingestion. REAL entries are published MCP servers pinned
 * to a release with a known advisory. Shown only when /api/mcs/config reports
 * demoMode.
 */
const MCSTestbed = (() => {
  // [branch, threat, correct verdict]
  const CASES = [
    ['clean-weather-py', 'clean', 'PASS'],
    ['rugpull-weather-py', 'rug pull (command injection)', 'FAIL'],
    ['safe-sql-ts', 'preference manipulation (description)', 'REVIEW'],
    ['rugpull-sql-ts', 'rug pull (SQL injection)', 'FAIL'],
    ['cmd-injection-shell-runner-py', 'command injection (CWE-78)', 'FAIL'],
    ['cmd-injection-os-system-py', 'command injection (CWE-78)', 'FAIL'],
    ['cmd-injection-fstring-py', 'command injection (CWE-78)', 'FAIL'],
    ['cmd-injection-aliased-import-py', 'command injection (CWE-78)', 'FAIL'],
    ['cmd-injection-helper-py', 'command injection (CWE-78)', 'FAIL'],
    ['cmd-injection-getattr-py', 'command injection (CWE-78), obfuscated', 'FAIL'],
    ['cmd-injection-exec-ts', 'command injection (CWE-78)', 'FAIL'],
    ['code-injection-eval-py', 'code injection (CWE-94)', 'FAIL'],
    ['deserialization-pickle-py', 'unsafe deserialization (CWE-502)', 'FAIL'],
    ['path-traversal-py', 'path traversal (CWE-22)', 'FAIL'],
    ['path-traversal-ts', 'path traversal (CWE-22)', 'FAIL'],
    ['ssrf-py', 'SSRF (CWE-918)', 'FAIL'],
    ['sqli-fstring-py', 'SQL injection (CWE-89)', 'FAIL'],
    ['backdoor-hardcoded-py', 'backdoor (hidden hardcoded command)', 'FAIL'],
    ['hidden-dist-entrypoint-ts', 'hiding: committed dist/ differs from src/', 'FAIL'],
    ['hidden-skipped-dir-py', 'hiding: runtime code under examples/', 'FAIL'],
    ['runtime-description-py', 'coverage: description built at runtime', 'REVIEW'],
    ['tool-poisoning-param-py', 'tool poisoning (parameter description)', 'FAIL'],
    ['tool-poisoning-zero-width-py', 'tool poisoning (zero-width characters)', 'FAIL'],
    ['tool-poisoning-classic-py', 'tool poisoning (<IMPORTANT> block)', 'FAIL'],
    ['tool-shadowing-py', 'tool shadowing', 'FAIL'],
    ['benign-subprocess-argv-py', 'clean', 'PASS'],
    ['benign-shlex-py', 'clean', 'PASS'],
    ['benign-utility-py', 'clean', 'PASS'],
    ['benign-execfile-ts', 'clean', 'PASS'],
    ['benign-ts', 'clean', 'PASS'],
    ['benign-security-words-py', 'clean', 'PASS'],
    ['unsupported-go', 'coverage: unsupported language', 'REVIEW'],
    ['watcher-demo', 'live rug pull (push the bait commit, then Poll Now)', 'PASS'],
  ];
  // Real releases with a published advisory: [repo, vulnerable tag, threat]
  const REAL = [
    ['https://github.com/BurtTheCoder/mcp-maigret', 'v1.0.12', 'command injection'],
    ['https://github.com/cyanheads/git-mcp-server', 'v2.1.4', 'command injection'],
    ['https://github.com/jamubc/gemini-mcp-tool', 'v1.1.5', 'command injection'],
    ['https://github.com/translated/lara-mcp', 'v0.0.11', 'command injection'],
    ['https://github.com/ooples/token-optimizer-mcp', 'v5.0.1', 'command injection, path traversal'],
    ['https://github.com/mobile-next/mobile-mcp', '0.0.48', 'path traversal'],
    ['https://github.com/haris-musa/excel-mcp-server', 'v0.1.7', 'path traversal'],
    ['https://github.com/Wolfe-Jam/claude-faf-mcp', 'v5.7.1', 'path traversal'],
    ['https://github.com/pipeboard-co/meta-ads-mcp', '1.0.113', 'SSRF'],
    ['https://github.com/apache/doris-mcp-server', '0.6.0', 'SQL injection'],
  ];

  let repo = null;
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  function entries() {
    return [
      ...CASES.map(([branch, threat, expect]) => ({
        key: 'case:' + branch, group: 'Testbed cases', label: `${branch} (${threat}) → ${expect}`,
        name: `Testbed ${branch}`, url: `${repo}/tree/${branch}`,
        description: `Testbed case: ${threat}`, longDescription: `MCP Secure testbed branch ${branch}. Correct verdict: ${expect}.`,
      })),
      ...REAL.map(([url, tag, threat]) => {
        const name = url.split('/').slice(-1)[0];
        return {
          key: 'real:' + name, group: 'Real advisories (vulnerable release)', label: `${name}@${tag} (${threat})`,
          name: `${name} ${tag}`, url: `${url}/tree/${tag}`,
          description: `Published MCP server at a release with a known ${threat} advisory.`,
          longDescription: `${url} at tag ${tag} (vulnerable release).`,
        };
      }),
    ];
  }

  /** Fill `select` with the cases; hide `wrapper` outside demo mode. onPick(entry) on change. */
  async function mount(select, wrapper, onPick) {
    const cfg = await fetch('/api/mcs/config').then(r => r.json()).catch(() => ({}));
    if (!cfg.demoMode || !cfg.testbedRepo) { if (wrapper) wrapper.style.display = 'none'; return; }
    repo = cfg.testbedRepo.replace(/\/$/, '');
    const list = entries();
    const groups = [...new Set(list.map(e => e.group))];
    select.innerHTML = '<option value="">— Pick a live test case —</option>' + groups.map(g =>
      `<optgroup label="${esc(g)}">${list.filter(e => e.group === g).map(e => `<option value="${esc(e.key)}">${esc(e.label)}</option>`).join('')}</optgroup>`).join('');
    if (wrapper) wrapper.style.display = '';
    select.addEventListener('change', () => {
      const e = list.find(x => x.key === select.value);
      if (e) onPick(e);
    });
  }

  return { mount, CASES, REAL };
})();
