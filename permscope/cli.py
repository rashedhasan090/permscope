"""Infer the GITHUB_TOKEN scopes a workflow actually needs and diff them against what it grants.

Stdlib only. Uses an indentation-aware mini parser that understands the subset of YAML
GitHub workflows use for `permissions:`, `jobs:`, `uses:` and `run:`.
"""
import argparse, json, os, re, sys

LEVEL = {"none": 0, "read": 1, "write": 2}
SCOPES = ["actions", "attestations", "checks", "contents", "deployments", "discussions",
          "id-token", "issues", "packages", "pages", "pull-requests", "security-events", "statuses"]

# action prefix -> needed scopes
ACTION_RULES = [
    (r"^actions/checkout@", {"contents": "read"}),
    (r"^actions/upload-pages-artifact@", {}),
    (r"^actions/deploy-pages@", {"pages": "write", "id-token": "write"}),
    (r"^actions/attest", {"attestations": "write", "id-token": "write"}),
    (r"^actions/github-script@", {}),
    (r"^actions/stale@", {"issues": "write", "pull-requests": "write"}),
    (r"^actions/labeler@", {"contents": "read", "pull-requests": "write"}),
    (r"^github/codeql-action/", {"security-events": "write", "contents": "read", "actions": "read"}),
    (r"^docker/login-action@", {}),
    (r"^aws-actions/configure-aws-credentials@", {"id-token": "write"}),
    (r"^google-github-actions/auth@", {"id-token": "write"}),
    (r"^azure/login@", {"id-token": "write"}),
    (r"^softprops/action-gh-release@", {"contents": "write"}),
    (r"^peter-evans/create-pull-request@", {"contents": "write", "pull-requests": "write"}),
    (r"^peter-evans/create-or-update-comment@", {"issues": "write", "pull-requests": "write"}),
    (r"^marocchino/sticky-pull-request-comment@", {"pull-requests": "write"}),
    (r"^stefanzweifel/git-auto-commit-action@", {"contents": "write"}),
    (r"^dependabot/fetch-metadata@", {"pull-requests": "read"}),
]
# shell command pattern -> needed scopes
RUN_RULES = [
    (r"\bgit\s+push\b", {"contents": "write"}),
    (r"\bgh\s+release\s+(create|upload|edit|delete)\b", {"contents": "write"}),
    (r"\bgh\s+pr\s+(create|merge|edit|close|review|comment)\b", {"pull-requests": "write"}),
    (r"\bgh\s+pr\s+(view|list|diff|checks)\b", {"pull-requests": "read"}),
    (r"\bgh\s+issue\s+(create|edit|close|comment|reopen)\b", {"issues": "write"}),
    (r"\bgh\s+issue\s+(view|list)\b", {"issues": "read"}),
    (r"\bgh\s+(run|workflow)\s+(rerun|run|cancel|enable|disable)\b", {"actions": "write"}),
    (r"\bgh\s+run\s+(view|list|download)\b", {"actions": "read"}),
    (r"docker\s+push\s+ghcr\.io", {"packages": "write"}),
    (r"\bnpm\s+publish\b.*npm\.pkg\.github\.com|npm\.pkg\.github\.com.*\bnpm\s+publish\b", {"packages": "write"}),
    (r"ACTIONS_ID_TOKEN_REQUEST", {"id-token": "write"}),
    (r"--provenance\b", {"id-token": "write"}),
]

def _merge(dst, src):
    for k, v in src.items():
        if LEVEL[v] > LEVEL.get(dst.get(k, "none"), 0):
            dst[k] = v

def _strip(line):
    out, q = [], None
    for i, ch in enumerate(line):
        if q:
            if ch == q: q = None
        elif ch in "'\"": q = ch
        elif ch == "#" and (i == 0 or line[i-1].isspace()): break
        out.append(ch)
    return "".join(out).rstrip()

def parse(text):
    """Return {'perms': top-level perms or None, 'jobs': {name: {'perms','uses','runs','line'}}}."""
    lines = text.splitlines()
    wf = {"perms": None, "jobs": {}}
    i, n = 0, len(lines)
    def indent(s): return len(s) - len(s.lstrip(" "))
    def read_perms(idx, base, val):
        val = val.strip().strip("'\"")
        if val:
            if val in ("read-all", "write-all"):
                lvl = val.split("-")[0]
                return {s: lvl for s in SCOPES}, idx + 1, val
            if val.startswith("{"):
                d = {}
                for part in val.strip("{}").split(","):
                    if ":" in part:
                        k, v = part.split(":", 1); d[k.strip()] = v.strip().strip("'\"")
                return d, idx + 1, None
            return {}, idx + 1, val
        d, j = {}, idx + 1
        while j < n:
            s = _strip(lines[j])
            if not s.strip(): j += 1; continue
            if indent(s) <= base: break
            if ":" in s:
                k, v = s.strip().split(":", 1); d[k.strip()] = v.strip().strip("'\"")
            j += 1
        return d, j, None
    cur_job, job_indent, in_jobs, jobs_indent = None, None, False, None
    while i < n:
        raw = _strip(lines[i])
        if not raw.strip(): i += 1; continue
        ind, s = indent(raw), raw.strip()
        if s.startswith("- "): s2, ind2 = s[2:], ind + 2
        else: s2, ind2 = s, ind
        if ind == 0:
            in_jobs = s.startswith("jobs:"); cur_job = None
            if s.startswith("permissions:"):
                d, i, special = read_perms(i, 0, s.split(":", 1)[1])
                wf["perms"] = d; wf["perms_raw"] = special; continue
            i += 1; continue
        if in_jobs and jobs_indent is None: jobs_indent = ind
        if in_jobs and ind == jobs_indent and s.endswith(":"):
            cur_job = s[:-1].strip("'\"")
            wf["jobs"][cur_job] = {"perms": None, "perms_raw": None, "uses": [], "runs": [], "line": i + 1}
            job_indent = ind; i += 1; continue
        if cur_job:
            job = wf["jobs"][cur_job]
            if ind == job_indent + 2 and s.startswith("permissions:"):
                d, i, special = read_perms(i, ind, s.split(":", 1)[1])
                job["perms"] = d; job["perms_raw"] = special; continue
            if ind == job_indent + 2 and s.startswith("uses:"):
                job["uses"].append(s.split(":", 1)[1].strip().strip("'\"")); i += 1; continue
            m = re.match(r"(uses|run):\s*(.*)$", s2)
            if m:
                key, val = m.group(1), m.group(2).strip()
                if key == "uses":
                    job["uses"].append(val.strip("'\"")); i += 1; continue
                if val in ("|", ">", "|-", ">-", "|+", ">+"):
                    body, j = [], i + 1
                    while j < n and (not lines[j].strip() or indent(lines[j]) > ind2):
                        body.append(lines[j]); j += 1
                    job["runs"].append("\n".join(body)); i = j; continue
                job["runs"].append(val); i += 1; continue
        i += 1
    return wf

def needed(job):
    need = {}
    for u in job["uses"]:
        if u.startswith("./"):
            need.setdefault("contents", "read"); continue
        for pat, sc in ACTION_RULES:
            if re.search(pat, u): _merge(need, sc)
    for r in job["runs"]:
        for pat, sc in RUN_RULES:
            if re.search(pat, r): _merge(need, sc)
    return need

def analyze(path, text):
    wf, findings = parse(text), []
    for name, job in wf["jobs"].items():
        need = needed(job)
        if job["perms"] is not None:
            granted, raw, src = job["perms"], job["perms_raw"], "job"
        elif wf["perms"] is not None:
            granted, raw, src = wf["perms"], wf.get("perms_raw"), "workflow"
        else:
            granted, raw, src = None, None, "default"
        rec = {"file": path, "job": name, "line": job["line"], "needed": need,
               "granted_from": src, "issues": []}
        if granted is None:
            rec["issues"].append({"severity": "high", "kind": "no-permissions",
                "msg": "no permissions block; token falls back to repo default (often write-all)"})
        else:
            if raw == "write-all":
                rec["issues"].append({"severity": "high", "kind": "write-all", "msg": "write-all grants every scope write"})
            for sc in sorted(set(need) | set(granted)):
                g, w = LEVEL.get(granted.get(sc, "none"), 0), LEVEL[need.get(sc, "none")]
                if w > g:
                    rec["issues"].append({"severity": "high", "kind": "missing", "scope": sc,
                        "msg": f"{sc}: needs {need[sc]} but granted {granted.get(sc,'none')} (job will likely fail)"})
                elif g > w and raw != "write-all":
                    sev = "medium" if granted[sc] == "write" else "low"
                    rec["issues"].append({"severity": sev, "kind": "excess", "scope": sc,
                        "msg": f"{sc}: granted {granted[sc]} but only {need.get(sc,'none')} is evidenced"})
        rec["suggested"] = need or {"contents": "none"}
        findings.append(rec)
    return findings

def collect(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith((".yml", ".yaml")) and ".github" + os.sep + "workflows" in os.path.join(root, f):
                        yield os.path.join(root, f)
        else:
            yield p

def render_yaml(d):
    return "permissions:\n" + "\n".join(f"  {k}: {v}" for k, v in sorted(d.items()))

def main(argv=None):
    ap = argparse.ArgumentParser(prog="permscope", description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*", default=["."])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-on", choices=["low", "medium", "high"], default=None)
    a = ap.parse_args(argv)
    allf = []
    for f in collect(a.paths):
        with open(f, encoding="utf-8") as fh:
            allf += analyze(f, fh.read())
    if a.json:
        print(json.dumps(allf, indent=2))
    else:
        for r in allf:
            print(f"{r['file']}:{r['line']} job '{r['job']}' (perms from {r['granted_from']})")
            for iss in r["issues"]:
                print(f"  [{iss['severity']}] {iss['msg']}")
            if not r["issues"]:
                print("  ok, least privilege")
            print("  suggested:\n    " + render_yaml(r["suggested"]).replace("\n", "\n    "))
    if a.fail_on:
        th = {"low": 1, "medium": 2, "high": 3}
        rank = {"low": 1, "medium": 2, "high": 3}
        if any(rank[i["severity"]] >= th[a.fail_on] for r in allf for i in r["issues"]):
            return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
