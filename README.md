# python-security-scan

Reachability-filtered `pip-audit` for Python CI, as a reusable composite
action. Runs `pip-audit` against a uv-managed Python project, diffs against a
cached state file, then asks an LLM (via [opencode] + OpenRouter) whether each
*new* vulnerability is actually reachable from the entry points you declare.
Only new + reachable CVEs surface as job failures (and optional Pushover
alerts).

The motivation: most dependency CVE alerts in real projects are noise. A
[2022 Semgrep study][semgrep-reachability] found roughly 2% of dep alerts in a
sample of OSS projects were reachable. Off-the-shelf scanners can't tell —
they flag every transitively-pulled package whose version matches an
advisory, regardless of whether your code ever calls into the vulnerable API.
This action uses an LLM with code-search tools to make that judgment call,
caches its verdict, and only re-asks for newly-introduced vulnerabilities.

There are several existing actions that wrap pip-audit (e.g.
[`pypa/gh-action-pip-audit`][pypa-action]) and several commercial reachability
products (Aikido, Semgrep). This action is the first OSS combination of the
two that I'm aware of, scoped narrowly to Python.

[opencode]: https://opencode.ai
[semgrep-reachability]: https://semgrep.dev/blog/2022/by-the-numbers-best-and-worst-vulnerable-dependencies-in-modern-applications/
[pypa-action]: https://github.com/pypa/gh-action-pip-audit

## Scope and assumptions

This action is **Python-specific**:

- Requires a `pyproject.toml` at the repository root that `uv run pip-audit`
  can resolve. uv is the assumed package manager; `[dependency-groups]` is
  parsed to skip dev-only packages.
- Scans the resolved Python dependency graph only — non-Python deps are out
  of scope.
- The reachability prompt reasons about Python module/import semantics; the
  `entry-points` input should describe Python entry points specifically.

The action is composite, so it runs on whatever runner the calling job
selects. Tested on `ubuntu-latest` with GitHub Actions and Gitea Actions
(which proxies GitHub-hosted actions transparently).

## Usage

```yaml
name: Daily security scan
on:
  schedule:
    - cron: '0 6 * * *'
  workflow_dispatch: {}

jobs:
  pip-audit-reachable:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    env:
      OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
      PUSHOVER_USER_KEY:  ${{ secrets.PUSHOVER_USER_KEY }}
      PUSHOVER_APP_KEY:   ${{ secrets.PUSHOVER_APP_KEY }}
    steps:
      - uses: actions/checkout@v4
      - uses: peakford/python-security-scan@v1
        with:
          project-name: my-project
          notification-title: 'my-project: new reachable CVE'
          entry-points: |
            - HTTP handlers in src/*/views.py
            - Background tasks in src/*/tasks.py
            - CLI entry points declared in pyproject.toml [project.scripts]
            - Module-level / import-time code (settings, signal handlers)
```

The action does **not** check out the repository for you — add
`actions/checkout@v4` (or equivalent) before this step.

## Inputs

| name                 | required | default                                  | purpose |
|----------------------|----------|------------------------------------------|---------|
| `project-name`       | yes      | —                                        | Used for the state filename and default Pushover title. Casing is preserved. |
| `entry-points`       | yes      | —                                        | Multi-line text injected into the opencode prompt under "Entry points to consider". |
| `model`              | no       | `z-ai/glm-5.1`                           | OpenRouter model id, passed to opencode as `openrouter/<model>`. |
| `notify`             | no       | `true`                                   | Whether to send a Pushover alert when a new reachable CVE is found. |
| `notification-title` | no       | `<project-name>: new reachable CVE`      | Pushover notification title. |
| `state-key-file`     | no       | `uv.lock`                                | File whose hash invalidates the persisted scan state cache. |
| `python-script-args` | no       | —                                        | Escape hatch for extra flags to `security_scan_ci.py`. |

## Required secrets

Pass these as job-level `env:` (not as inputs), so they aren't exposed to
composite-action inspection:

| env var             | required | purpose |
|---------------------|----------|---------|
| `OPENROUTER_API_KEY`| yes      | Consumed by opencode to call the chosen model. |
| `PUSHOVER_USER_KEY` | when notifying | Pushover user key. |
| `PUSHOVER_APP_KEY`  | when notifying | Pushover application token. |

When `notify: true` but Pushover keys are missing, the script logs and
continues — the job still fails on a reachable CVE so you don't miss it.

## Exit codes

| code | meaning |
|------|---------|
| 0    | no new reachable vulns (or no vulns at all) |
| 1    | at least one new reachable vuln; concise summary on stdout |
| 2    | internal error (pip-audit crashed, unparseable JSON, missing required env, ...) |

## Running the script standalone

The script is also runnable outside the action, against any uv project:

```sh
SCAN_PROJECT=myproj \
SCAN_ENTRY_POINTS='- handlers in app/views.py' \
uv run python scripts/security_scan_ci.py
```

State persists under `$STATE_DIR` (default `~/.cache/security-scan-ci/`).

## Versioning

Releases are tagged `vMAJOR.MINOR.PATCH`. A moving `v1` tag tracks the latest
1.x release; pin to `@v1` in `uses:`. Breaking input changes bump the major.

## License

MIT
