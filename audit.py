import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

VERSION = "1.0.0"
API = "https://api.github.com"

CHECKS = {
    "dependabot_alerts": "Dependabot alerts",
    "security_updates": "Dependabot security updates",
    "dependabot_config": "Dependabot version updates (dependabot.yml)",
    "secret_scanning": "Secret scanning",
    "push_protection": "Push protection",
    "private_reporting": "Private vulnerability reporting",
    "code_scanning": "Code scanning",
    "branch_protection": "Branch protection on the default branch",
    "security_policy": "Security policy (SECURITY.md)",
}
SHORT = {
    "dependabot_alerts": "Alerts",
    "security_updates": "Updates",
    "dependabot_config": "Config",
    "secret_scanning": "Secrets",
    "push_protection": "Push",
    "private_reporting": "Reporting",
    "code_scanning": "Code scan",
    "branch_protection": "Branch",
    "security_policy": "Policy",
}


def make_api(token):
    def api(path):
        url = path if path.startswith("http") else API + path
        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"repo-security-audit/{VERSION}",
        })
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read()
                return response.status, json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
    return api


def config_token():
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import config
        return getattr(config, "GITHUB_TOKEN", None) or None
    except ImportError:
        return None


def _pages(api, path):
    page = 1
    while True:
        status, body = api(f"{path}?per_page=100&page={page}")
        if status != 200 or not body:
            return
        yield from body
        if len(body) < 100:
            return
        page += 1


def list_repos(owner, api, include_archived=False, include_forks=True):
    status, _ = api(f"/orgs/{owner}")
    path = f"/orgs/{owner}/repos" if status == 200 else f"/users/{owner}/repos"
    repos = []
    for r in _pages(api, path):
        if r.get("archived") and not include_archived:
            continue
        if r.get("fork") and not include_forks:
            continue
        repos.append(r)
    return sorted(repos, key=lambda r: r["name"].lower())


def _result(ok, note=""):
    return {"ok": ok, "note": note}


def _exists(api, path):
    status, _ = api(path)
    return status == 200


def audit_repo(r, api, owner_policy=False):
    base = f"/repos/{r['full_name']}"
    checks = {}

    status, _ = api(f"{base}/vulnerability-alerts")
    checks["dependabot_alerts"] = _result(None, "no access") if status == 403 else _result(status == 204)

    status, body = api(f"{base}/automated-security-fixes")
    checks["security_updates"] = (_result(None, "no access") if status == 403
                                  else _result(status == 200 and bool((body or {}).get("enabled"))))

    checks["dependabot_config"] = _result(
        _exists(api, f"{base}/contents/.github/dependabot.yml") or _exists(api, f"{base}/contents/.github/dependabot.yaml"))

    analysis = r.get("security_and_analysis")
    for key, field in (("secret_scanning", "secret_scanning"), ("push_protection", "secret_scanning_push_protection")):
        if analysis is None:
            checks[key] = _result(None, "no access")
        else:
            checks[key] = _result((analysis.get(field) or {}).get("status") == "enabled")

    status, body = api(f"{base}/private-vulnerability-reporting")
    checks["private_reporting"] = (_result(None, "no access") if status == 403
                                   else _result(status == 200 and bool((body or {}).get("enabled"))))

    status, body = api(f"{base}/code-scanning/default-setup")
    if status == 200 and (body or {}).get("state") == "configured":
        checks["code_scanning"] = _result(True, "default setup")
    else:
        status, body = api(f"{base}/code-scanning/analyses?per_page=1")
        checks["code_scanning"] = _result(True, "workflow") if status == 200 and body else _result(False)

    branch = r.get("default_branch") or "main"
    status, _ = api(f"{base}/branches/{branch}/protection")
    if status == 200:
        checks["branch_protection"] = _result(True, "branch rule")
    else:
        rs_status, rules = api(f"{base}/rules/branches/{branch}")
        if rs_status == 200 and rules:
            checks["branch_protection"] = _result(True, "ruleset")
        elif status == 403 and r.get("private"):
            checks["branch_protection"] = _result(None, "not on this plan")
        else:
            checks["branch_protection"] = _result(False)

    if any(_exists(api, f"{base}/contents/{p}") for p in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")):
        checks["security_policy"] = _result(True)
    elif owner_policy:
        checks["security_policy"] = _result(True, "owner default")
    else:
        checks["security_policy"] = _result(False)

    status, languages = api(f"{base}/languages")
    if status == 200 and not languages:
        for key in ("security_updates", "dependabot_config", "code_scanning"):
            if checks[key]["ok"] is False:
                checks[key] = _result(None, "no code")

    gaps = [CHECKS[k] for k, v in checks.items() if v["ok"] is False]
    return {"repo": r, "checks": checks, "gaps": gaps}


def _cell(check):
    mark = {True: "✅", False: "❌", None: "—"}[check["ok"]]
    return f"{mark} {check['note']}".strip()


def report(owner, results):
    results = sorted(results, key=lambda x: (-len(x["gaps"]), x["repo"]["name"].lower()))
    passing = sum(1 for x in results if not x["gaps"])
    lines = [
        f"# Security audit: {owner}",
        "",
        f"{passing} of {len(results)} repositories pass every check.",
        "",
        "| Repository | " + " | ".join(SHORT[k] for k in CHECKS) + " |",
        "|---|" + "---|" * len(CHECKS),
    ]
    for x in results:
        r = x["repo"]
        name = f"[{r['name']}]({r['html_url']})" + (" (fork)" if r.get("fork") else "") + (" (private)" if r.get("private") else "")
        lines.append(f"| {name} | " + " | ".join(_cell(x["checks"][k]) for k in CHECKS) + " |")
    lines += ["", "✅ on · ❌ off · — not checked (no code, no admin access, or not available on this plan)", ""]
    lines += ["Columns: " + "; ".join(f"**{SHORT[k]}**: {v}" for k, v in CHECKS.items()) + "."]
    to_fix = [x for x in results if x["gaps"]]
    if to_fix:
        lines += ["", "## To fix"]
        for x in to_fix:
            lines += ["", f"### {x['repo']['name']}", ""] + [f"- {g}" for g in x["gaps"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit the security settings of every repository a GitHub user or organisation owns.")
    parser.add_argument("owner", help="GitHub organisation or user name")
    parser.add_argument("-o", "--output", help="also write the Markdown report to this file")
    parser.add_argument("--include-archived", action="store_true", help="include archived repositories")
    parser.add_argument("--no-forks", action="store_true", help="leave out forks")
    parser.add_argument("--fail-on-gaps", action="store_true", help="exit 1 if any repository fails a check")
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or config_token()
    if not token:
        print("Set GITHUB_TOKEN (or GITHUB_TOKEN in config.py) to a token with admin access to the repositories.",
              file=sys.stderr)
        return 2

    api = make_api(token)
    repos = list_repos(args.owner, api, include_archived=args.include_archived, include_forks=not args.no_forks)
    owner_policy = any(
        _exists(api, f"/repos/{args.owner}/.github/contents/{p}") for p in ("SECURITY.md", ".github/SECURITY.md"))
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda r: audit_repo(r, api, owner_policy), repos))
    text = report(args.owner, results)
    print(text)
    if args.output:
        Path(args.output).write_text(text)
    return 1 if args.fail_on_gaps and any(x["gaps"] for x in results) else 0


if __name__ == "__main__":
    sys.exit(main())
