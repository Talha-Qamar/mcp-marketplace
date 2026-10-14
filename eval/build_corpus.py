#!/usr/bin/env python3
"""Build eval/corpus.json: real MCP servers with published vulnerabilities.

Ground truth comes from the GitHub Advisory Database. For every advisory whose
package name mentions MCP and whose CWE is one the pipeline targets, this
resolves two git tags in the advisory's source repository:

  vulnerable  the highest released version inside the vulnerable range
  fixed       the first patched version (when the advisory names one)

Cases are deduplicated per (repository, vulnerable tag): one repository with
20 advisories against the same release is one case, with all its CWEs.

Usage: python eval/build_corpus.py      (needs `gh` authenticated and `git`)
"""

import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CWES = ["77", "78", "88", "94", "95", "22", "59", "73", "89", "918", "502"]
ECOSYSTEMS = ["npm", "pip"]

# Not MCP servers: SDKs/frameworks, clients, proxies, gateways, generators,
# inspectors. Their vulnerabilities are real but not what a server gate scans.
EXCLUDE = {
    "PrefectHQ/fastmcp": "framework", "jlowin/fastmcp": "framework", "agentfront/frontmcp": "framework",
    "orval-labs/orval": "code generator", "wong2/mcp-cli": "client", "geelen/mcp-remote": "client proxy",
    "modelcontextprotocol/inspector": "inspector", "IBM/mcp-context-forge": "gateway",
    "samanhappy/mcphub": "hub/proxy", "akoskm/create-mcp-server-stdio": "generator",
    "getsimpletool/mcpo-simple-server": "proxy", "microsoft/mcp": "monorepo (unmapped)",
}
# Monorepos: package name -> subdirectory holding that server.
MONOREPO_PATHS = {
    ("modelcontextprotocol/servers", "@modelcontextprotocol/server-filesystem"): "src/filesystem",
    ("modelcontextprotocol/servers", "mcp-server-git"): "src/git",
}

CWE_THREAT = {
    "CWE-77": "command_injection", "CWE-78": "command_injection", "CWE-88": "command_injection",
    "CWE-94": "code_injection", "CWE-95": "code_injection",
    "CWE-22": "path_traversal", "CWE-59": "path_traversal", "CWE-73": "path_traversal",
    "CWE-89": "sql_injection", "CWE-918": "ssrf", "CWE-502": "unsafe_deserialization",
}

VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?$")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def advisories():
    out = {}
    for cwe in CWES:
        for eco in ECOSYSTEMS:
            r = run(["gh", "api", "--paginate", "--slurp", f"/advisories?cwes={cwe}&ecosystem={eco}&per_page=100"])
            if r.returncode != 0:
                print("gh api failed:", r.stderr[:200], file=sys.stderr)
                continue
            for page in json.loads(r.stdout or "[]"):  # --slurp: one array per page
                for a in page:
                    names = " ".join(v["package"]["name"] for v in a["vulnerabilities"] if v.get("package"))
                    if re.search("mcp", names, re.I) and not a.get("withdrawn_at"):
                        out[a["ghsa_id"]] = a
    return list(out.values())


def parse_ver(s):
    m = VER_RE.search(s or "")
    return tuple(int(x or 0) for x in m.groups()) if m else None


def satisfies(ver, rng):
    for part in [p.strip() for p in (rng or "").split(",") if p.strip()]:
        m = re.match(r"(<=|>=|<|>|=)?\s*v?([\d.]+)", part)
        if not m:
            return False
        op, target = m.group(1) or "=", parse_ver(m.group(2))
        if target is None:
            return False
        if not {"<": ver < target, "<=": ver <= target, ">": ver > target, ">=": ver >= target, "=": ver == target}[op]:
            return False
    return True


def tags(repo):
    r = run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"])
    found = {}
    for line in r.stdout.splitlines():
        sha, ref = line.split("\t")
        name = ref[len("refs/tags/"):]
        peeled = name.endswith("^{}")
        name = name[:-3] if peeled else name
        if re.search(r"(alpha|beta|rc|pre|dev|canary|next)", name, re.I):
            continue
        if name not in found or peeled:  # prefer the peeled commit of an annotated tag
            found[name] = sha
    return found


def tag_for(tag_map, version_tuple, pkg):
    """Pick the tag naming exactly this version (v1.2.3, 1.2.3, pkg@1.2.3, pkg-v1.2.3, …)."""
    short = pkg.split("/")[-1]
    best = None
    for name, sha in tag_map.items():
        v = parse_ver(name)
        if v != version_tuple:
            continue
        prefix = name[: VER_RE.search(name).start()].rstrip("v@-_/").lower()
        score = 0 if prefix == "" else 1 if short.lower() in prefix or prefix in short.lower() else 2
        if best is None or score < best[0]:
            best = (score, name, sha)
    return best and best[0] < 2 and (best[1], best[2])


def main():
    cases, skipped = {}, []
    for a in sorted(advisories(), key=lambda x: x["ghsa_id"]):
        src = (a.get("source_code_location") or "").rstrip("/")
        m = re.match(r"https://github\.com/([^/]+/[^/#]+)", src)
        if not m:
            skipped.append((a["ghsa_id"], "no GitHub source")); continue
        repo = re.sub(r"\.git$", "", m.group(1))
        if repo in EXCLUDE:
            skipped.append((a["ghsa_id"], f"{repo}: {EXCLUDE[repo]}")); continue
        vuln = next((v for v in a["vulnerabilities"] if v.get("package") and re.search("mcp", v["package"]["name"], re.I)), None)
        pkg = vuln["package"]["name"]
        subdir = MONOREPO_PATHS.get((repo, pkg))
        if repo == "modelcontextprotocol/servers" and not subdir:
            skipped.append((a["ghsa_id"], f"monorepo path unknown for {pkg}")); continue
        tmap = tags(repo)
        versions = sorted({v for v in (parse_ver(t) for t in tmap) if v and satisfies(v, vuln["vulnerable_version_range"])})
        if not versions:
            skipped.append((a["ghsa_id"], f"{repo}: no tag in range {vuln['vulnerable_version_range']}")); continue
        vt = tag_for(tmap, versions[-1], pkg)
        if not vt:
            skipped.append((a["ghsa_id"], f"{repo}: ambiguous tag for {versions[-1]}")); continue
        fixed = None
        if vuln.get("first_patched_version"):
            fx = tag_for(tmap, parse_ver(vuln["first_patched_version"]), pkg)
            fixed = fx and {"tag": fx[0], "commit": fx[1]}
        key = (repo, vt[1])
        cwes = sorted({c["cwe_id"] for c in a["cwes"]})
        case = cases.setdefault(key, {
            "id": f"{repo.replace('/', '__')}@{vt[0]}",
            "repo": f"https://github.com/{repo}",
            "subdir": subdir,
            "package": f"{vuln['package']['ecosystem']}:{pkg}",
            "vulnerable": {"tag": vt[0], "commit": vt[1]},
            "fixed": fixed,
            "advisories": [],
            "cwes": [],
        })
        case["advisories"].append({"ghsa": a["ghsa_id"], "cve": a.get("cve_id"), "severity": a["severity"],
                                   "published": a["published_at"][:10], "summary": a["summary"][:140]})
        case["cwes"] = sorted(set(case["cwes"]) | set(cwes))
        case["threats"] = sorted({CWE_THREAT[c] for c in case["cwes"] if c in CWE_THREAT})
        if fixed and not case["fixed"]:
            case["fixed"] = fixed
    corpus = sorted(cases.values(), key=lambda c: c["id"])
    (HERE / "corpus.json").write_text(json.dumps({"generated_by": "eval/build_corpus.py", "cases": corpus,
                                                  "skipped": [{"ghsa": g, "reason": r} for g, r in skipped]}, indent=1) + "\n")
    print(f"{len(corpus)} cases ({sum(1 for c in corpus if c['fixed'])} with a fixed twin), {len(skipped)} advisories skipped")


if __name__ == "__main__":
    main()
