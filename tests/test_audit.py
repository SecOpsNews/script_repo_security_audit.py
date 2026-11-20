import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("audit", ROOT / "audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

ON = {"status": "enabled"}
OFF = {"status": "disabled"}


def repo(name, **extra):
    base = {
        "name": name, "full_name": f"acme/{name}", "default_branch": "main", "private": False,
        "archived": False, "fork": False, "html_url": f"https://github.com/acme/{name}",
        "security_and_analysis": {"secret_scanning": ON, "secret_scanning_push_protection": ON},
    }
    base.update(extra)
    return base


def secure_routes(name):
    r = f"/repos/acme/{name}"
    return {
        f"{r}/vulnerability-alerts": (204, None),
        f"{r}/automated-security-fixes": (200, {"enabled": True}),
        f"{r}/contents/.github/dependabot.yml": (200, {"name": "dependabot.yml"}),
        f"{r}/private-vulnerability-reporting": (200, {"enabled": True}),
        f"{r}/code-scanning/default-setup": (200, {"state": "configured"}),
        f"{r}/branches/main/protection": (200, {}),
        f"{r}/contents/SECURITY.md": (200, {"name": "SECURITY.md"}),
        f"{r}/languages": (200, {"Python": 1000}),
    }


class FakeAPI:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, path):
        self.calls.append(path)
        return self.routes.get(path.split("?")[0], (404, {"message": "Not Found"}))


def test_secure_repo_passes_every_check():
    api = FakeAPI(secure_routes("good"))
    result = audit.audit_repo(repo("good"), api)
    assert all(v["ok"] for v in result["checks"].values())
    assert result["gaps"] == []


def test_insecure_repo_reports_each_gap():
    r = repo("bad", security_and_analysis={"secret_scanning": OFF, "secret_scanning_push_protection": OFF})
    api = FakeAPI({"/repos/acme/bad/automated-security-fixes": (200, {"enabled": False}),
                   "/repos/acme/bad/languages": (200, {"Go": 10}),
                   "/repos/acme/bad/private-vulnerability-reporting": (200, {"enabled": False})})
    result = audit.audit_repo(r, api)
    assert not any(v["ok"] for v in result["checks"].values())
    assert len(result["gaps"]) == len(audit.CHECKS)


def test_code_scanning_from_a_workflow_counts():
    routes = secure_routes("wf")
    routes["/repos/acme/wf/code-scanning/default-setup"] = (200, {"state": "not-configured"})
    routes["/repos/acme/wf/code-scanning/analyses"] = (200, [{"tool": {"name": "CodeQL"}}])
    result = audit.audit_repo(repo("wf"), FakeAPI(routes))
    assert result["checks"]["code_scanning"] == {"ok": True, "note": "workflow"}


def test_ruleset_counts_as_branch_protection():
    routes = secure_routes("rs")
    del routes["/repos/acme/rs/branches/main/protection"]
    routes["/repos/acme/rs/rules/branches/main"] = (200, [{"type": "pull_request"}])
    result = audit.audit_repo(repo("rs"), FakeAPI(routes))
    assert result["checks"]["branch_protection"] == {"ok": True, "note": "ruleset"}


def test_dependabot_yaml_extension_and_security_policy_locations():
    routes = secure_routes("alt")
    del routes["/repos/acme/alt/contents/.github/dependabot.yml"]
    routes["/repos/acme/alt/contents/.github/dependabot.yaml"] = (200, {})
    del routes["/repos/acme/alt/contents/SECURITY.md"]
    routes["/repos/acme/alt/contents/.github/SECURITY.md"] = (200, {})
    result = audit.audit_repo(repo("alt"), FakeAPI(routes))
    assert result["checks"]["dependabot_config"]["ok"]
    assert result["checks"]["security_policy"]["ok"]


def test_owner_default_security_policy_counts():
    routes = secure_routes("inherits")
    del routes["/repos/acme/inherits/contents/SECURITY.md"]
    result = audit.audit_repo(repo("inherits"), FakeAPI(routes), owner_policy=True)
    assert result["checks"]["security_policy"] == {"ok": True, "note": "owner default"}


def test_no_admin_access_is_unknown_not_off():
    r = repo("theirs")
    del r["security_and_analysis"]
    routes = {"/repos/acme/theirs/vulnerability-alerts": (403, {"message": "Must have admin rights"})}
    result = audit.audit_repo(r, FakeAPI(routes))
    assert result["checks"]["dependabot_alerts"] == {"ok": None, "note": "no access"}
    assert result["checks"]["secret_scanning"] == {"ok": None, "note": "no access"}
    assert "Dependabot alerts" not in result["gaps"]


def test_lists_org_repos_with_pagination_and_filters():
    page1 = [repo(f"r{i}") for i in range(100)]
    page2 = [repo("old", archived=True), repo("copy", fork=True), repo("last")]
    api = FakeAPI({"/orgs/acme": (200, {"login": "acme"})})
    api.routes["/orgs/acme/repos"] = None

    def pages(path):
        api.calls.append(path)
        if path.startswith("/orgs/acme/repos"):
            return (200, page1) if "&page=1" in path else (200, page2) if "&page=2" in path else (200, [])
        return api.routes.get(path.split("?")[0], (404, {}))

    names = [r["name"] for r in audit.list_repos("acme", pages)]
    assert len(names) == 102 and "old" not in names and "copy" in names
    names = [r["name"] for r in audit.list_repos("acme", pages, include_archived=True, include_forks=False)]
    assert "old" in names and "copy" not in names


def test_falls_back_to_user_repos():
    def api(path):
        if path.startswith("/orgs/"):
            return 404, {}
        if path.startswith("/users/someone/repos"):
            return (200, [repo("mine")]) if "&page=1" in path else (200, [])
        return 404, {}

    assert [r["name"] for r in audit.list_repos("someone", api)] == ["mine"]


def test_report_has_table_score_and_fix_list():
    good = {"repo": repo("good"), "checks": {k: {"ok": True, "note": ""} for k in audit.CHECKS}, "gaps": []}
    bad_checks = {k: {"ok": True, "note": ""} for k in audit.CHECKS}
    bad_checks["secret_scanning"] = {"ok": False, "note": ""}
    bad_checks["branch_protection"] = {"ok": None, "note": "no access"}
    bad = {"repo": repo("bad"), "checks": bad_checks, "gaps": ["Secret scanning"]}
    text = audit.report("acme", [good, bad])
    assert text.splitlines()[0] == "# Security audit: acme"
    assert "1 of 2 repositories pass every check." in text
    assert "| [bad](https://github.com/acme/bad) |" in text
    assert "### bad" in text and "- Secret scanning" in text
    assert "### good" not in text
    assert text.index("[bad]") < text.index("[good]")


def test_cli_writes_report_and_exit_codes(tmp_path, monkeypatch):
    routes = secure_routes("good")
    routes["/orgs/acme"] = (200, {})

    def api(path):
        if path.startswith("/orgs/acme/repos"):
            return (200, [repo("good")]) if "&page=1" in path else (200, [])
        return routes.get(path.split("?")[0], (404, {}))

    monkeypatch.setattr(audit, "make_api", lambda token: api)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    out = tmp_path / "audit.md"
    assert audit.main(["acme", "-o", str(out)]) == 0
    assert "1 of 1 repositories pass every check." in out.read_text()
    routes["/repos/acme/good/vulnerability-alerts"] = (404, {})
    assert audit.main(["acme"]) == 0
    assert audit.main(["acme", "--fail-on-gaps"]) == 1


def test_cli_needs_a_token(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setattr(audit, "config_token", lambda: None)
    assert audit.main(["acme"]) == 2
    assert "token" in capsys.readouterr().err


def test_repo_without_code_skips_code_checks():
    r = repo("docs")
    routes = {"/repos/acme/docs/vulnerability-alerts": (204, None),
              "/repos/acme/docs/private-vulnerability-reporting": (200, {"enabled": True}),
              "/repos/acme/docs/automated-security-fixes": (200, {"enabled": False}),
              "/repos/acme/docs/contents/SECURITY.md": (200, {}),
              "/repos/acme/docs/branches/main/protection": (200, {}),
              "/repos/acme/docs/languages": (200, {})}
    result = audit.audit_repo(r, FakeAPI(routes))
    for key in ("security_updates", "dependabot_config", "code_scanning"):
        assert result["checks"][key] == {"ok": None, "note": "no code"}
    assert result["gaps"] == []
