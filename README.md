# Repo security audit

> Check the security settings of every repository a GitHub user or organisation owns, and get a Markdown report of what's on, what's off and what to fix.

One file, Python standard library only, no installs.

## Requirements

- Python 3.11+
- A GitHub token with admin access to the repositories. Some settings, such as Dependabot alerts and secret scanning, are only visible to admins. A [fine-grained token](https://github.com/settings/personal-access-tokens) needs read access to Administration, Code scanning alerts, Contents, Metadata and Secret scanning alerts. A classic token needs `repo`. If you use the GitHub CLI, `gh auth token` gives you one.

## Setup

1. Clone the repo, or download `audit.py`.
2. Either set `GITHUB_TOKEN` in your environment, or copy `config.py.example` to `config.py` and put the token in it. `config.py` is ignored by git.

## Usage

```bash
GITHUB_TOKEN=$(gh auth token) python audit.py my-org
```

It works for organisations and users. To write the report to a file:

```bash
python audit.py my-org -o security-audit.md
```

- `--include-archived` also checks archived repositories.
- `--no-forks` leaves out forks.
- `--fail-on-gaps` exits with 1 if any repository fails a check, so it can fail a CI job.

### What it checks

| Check | Passes when |
|---|---|
| Dependabot alerts | Alerts are turned on |
| Dependabot security updates | Security update pull requests are turned on |
| Dependabot version updates | The repository has `.github/dependabot.yml` |
| Secret scanning | Secret scanning is turned on |
| Push protection | Push protection is turned on |
| Private vulnerability reporting | People can report vulnerabilities privately |
| Code scanning | CodeQL default setup is on, or a code scanning workflow has uploaded results |
| Branch protection | The default branch has a branch protection rule or a ruleset |
| Security policy | The repository has a `SECURITY.md`, or the owner's `.github` repository has one, which GitHub uses as the default |

Repositories with no code, such as a list or a settings repository, aren't marked down for Dependabot updates or code scanning. A check it can't see, because the token isn't an admin or the plan doesn't include it, is shown as not checked rather than off.

### A note on branch protection

Branch protection that requires pull requests stops workflows that commit straight to the default branch, such as ones that rebuild data or a site. For those repositories, a ruleset that blocks force pushes and branch deletion, with your automation allowed to bypass it, protects the history without breaking the workflow.

### In GitHub Actions

The default `GITHUB_TOKEN` in Actions can't read other repositories' security settings, so store a token with admin access as a secret:

```yaml
- uses: actions/checkout@v7
- run: python audit.py ${{ github.repository_owner }} -o security-audit.md
  env:
      GITHUB_TOKEN: ${{ secrets.AUDIT_TOKEN }}
- run: cat security-audit.md >> "$GITHUB_STEP_SUMMARY"
```

## Testing

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest tests
```

## Changes and Release

Increment the `package.json` version, using SemVer, when committing changes to the script, and keep `VERSION` in `audit.py` in step. The GitHub action creates a new release using the last commit message as the release note.

## Notes

Made by [thechelsuk](https://thechels.uk) for [SecOpsNews](https://secops.thechels.uk): security news, advisories and critical CVEs on one dashboard. MIT licensed: see [LICENSE](LICENSE).
