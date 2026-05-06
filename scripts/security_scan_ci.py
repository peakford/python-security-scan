#!/usr/bin/env python3
# security_scan_ci.py — pip-audit + opencode reachability filter for CI.
#
# Runs pip-audit against a uv-managed Python project, diffs against a cached
# state file, asks opencode (via OpenRouter) whether each new vuln is
# reachable from the project's declared entry points, and emits a summary
# (and optional Pushover alert) when at least one new + reachable CVE is
# confirmed.
#
# Required environment:
#   SCAN_PROJECT         project identifier (used for state filename + default
#                        Pushover title); preserve exact casing
#   SCAN_ENTRY_POINTS    multi-line text describing the project's entry points
#                        (HTTP handlers, task queues, CLI commands, ...) for
#                        the opencode reachability prompt
#
# Optional environment:
#   SCAN_MODEL                OpenRouter model id (default: z-ai/glm-5.1)
#   SCAN_NOTIFICATION_TITLE   Pushover title (default: "<project>: new reachable CVE")
#   STATE_DIR                 cache dir for state file (default: ~/.cache/security-scan-ci)
#   OPENROUTER_API_KEY        consumed by opencode itself
#   PUSHOVER_USER_KEY         + PUSHOVER_APP_KEY: enable Pushover delivery
#
# Exit codes:
#   0  no new reachable vulns (or no vulns at all)
#   1  at least one new reachable vuln; concise summary on stdout
#   2  internal error (pip-audit crashed, unparseable JSON, missing env, etc.)

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise ScannerError(f"required env var {name} is not set")
    return val


class ScannerError(Exception):
    pass


def log(msg: str) -> None:
    print(f"[security-scan-ci] {msg}", file=sys.stderr)


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write_json(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


def run_pip_audit() -> dict:
    proc = subprocess.run(
        ["uv", "run", "pip-audit",
         "--vulnerability-service", "osv",
         "--format", "json",
         "--progress-spinner", "off"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode not in (0, 1):
        raise ScannerError(
            f"pip-audit failed (exit {proc.returncode}):\n{proc.stderr}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError(
            f"pip-audit produced unparseable JSON (exit {proc.returncode}): "
            f"{e}\n{proc.stdout[:2000]}"
        ) from e


def extract_current_vulns(audit_data: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for dep in audit_data.get("dependencies", []):
        name = dep.get("name")
        ver = dep.get("version")
        for vuln in dep.get("vulns", []) or []:
            vid = vuln.get("id")
            key = f"{name}=={ver}:{vid}"
            out[key] = {
                "pkg": name,
                "ver": ver,
                "id": vid,
                "aliases": vuln.get("aliases") or [],
                "fix_versions": vuln.get("fix_versions") or [],
                "description": vuln.get("description") or "",
            }
    return out


def compute_diff(current: dict[str, dict], state: dict) -> list[str]:
    seen = (state or {}).get("seen") or {}
    return sorted(set(current.keys()) - set(seen.keys()))


def dev_only_packages(project_root: pathlib.Path) -> set[str]:
    pp = project_root / "pyproject.toml"
    if not pp.exists():
        return set()
    try:
        data = tomllib.loads(pp.read_text())
    except Exception:
        return set()

    def norm(spec) -> str:
        if not isinstance(spec, str):
            return ""
        for sep in "[<>=~;":
            spec = spec.split(sep)[0]
        return spec.strip().lower().replace("_", "-")

    prod = {norm(s) for s in data.get("project", {}).get("dependencies", []) if norm(s)}
    dev: set[str] = set()
    for group in data.get("dependency-groups", {}).values():
        for s in group:
            n = norm(s)
            if n:
                dev.add(n)
    return dev - prod


def _build_opencode_prompt(project_root: pathlib.Path, entry_points: str,
                           pkg: str, ver: str, vid: str,
                           aliases: str, fixes: str, desc: str) -> str:
    return (
        "You are checking whether a Python package vulnerability is reachable in this codebase.\n"
        "\n"
        f"PACKAGE: {pkg}=={ver}\n"
        f"VULN ID: {vid}\n"
        f"ALIASES: {aliases}\n"
        f"FIX VERSIONS: {fixes}\n"
        f"DESCRIPTION: {desc}\n"
        "\n"
        f"Project root: {project_root}\n"
        "Entry points to consider:\n"
        f"{entry_points.rstrip()}\n"
        "\n"
        "A vuln is REACHABLE only if the vulnerable API/feature is actually invoked\n"
        "from one of those entry points (transitively via imports). A dependency\n"
        "that is present only because another library vendors it — but which our\n"
        "own code never calls into a vulnerable surface of — is NOT reachable.\n"
        "\n"
        "Use the Grep/Read/Glob tools to confirm. Be efficient: 5-10 tool calls max.\n"
        "\n"
        "On the LAST line of your reply, output ONLY this JSON (no code fences, no extra text):\n"
        '{"reachable": true|false, "confidence": "high|medium|low", "note": "<=120 chars"}'
    )


def opencode_reach_check(project_root: pathlib.Path, entry_points: str,
                         model: str, vuln: dict) -> dict:
    prompt = _build_opencode_prompt(
        project_root, entry_points,
        vuln["pkg"], vuln["ver"], vuln["id"],
        ", ".join(vuln["aliases"]),
        ", ".join(vuln["fix_versions"]),
        vuln["description"],
    )
    try:
        proc = subprocess.run(
            ["opencode", "run",
             "--agent", "build",
             "--model", f"openrouter/{model}",
             "--format", "json",
             "--dangerously-skip-permissions",
             "--dir", str(project_root),
             "--", prompt],
            capture_output=True, text=True, timeout=300, check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        excerpt = str(e)[:200].replace('"', "'").replace("\n", " ")
        log(f"opencode invocation failed: {e}")
        return {"reachable": True, "confidence": "low",
                "note": f"opencode invocation failed: {excerpt}",
                "source": "error"}

    if proc.returncode != 0:
        log(f"opencode rc={proc.returncode}; stderr:")
        sys.stderr.write(proc.stderr[:2000])
        if not proc.stderr.endswith("\n"):
            sys.stderr.write("\n")
        excerpt = (proc.stderr[:200] or "no stderr").replace("\n", " ").replace('"', "'")
        return {"reachable": True, "confidence": "low",
                "note": f"opencode rc={proc.returncode}: {excerpt}",
                "source": "error"}

    text_chunks: list[str] = []
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("type") == "text":
            part = obj.get("part") or {}
            t = part.get("text") or ""
            if t:
                text_chunks.append(t)

    result_text = "".join(text_chunks)
    if not result_text:
        return {"reachable": True, "confidence": "low",
                "note": "empty opencode result envelope",
                "source": "error"}

    last = ""
    for line in result_text.splitlines():
        stripped = line.strip()
        if stripped:
            last = stripped
    verdict = None
    if last:
        try:
            cand = json.loads(last)
            if isinstance(cand, dict) and "reachable" in cand:
                verdict = cand
        except json.JSONDecodeError:
            verdict = None
    if verdict is None:
        return {"reachable": True, "confidence": "low",
                "note": "unparseable opencode verdict; review manually",
                "source": "error"}
    verdict["source"] = "opencode"
    return verdict


def verify_reachability(project_root: pathlib.Path, entry_points: str,
                        model: str, current: dict[str, dict],
                        new_keys: list[str], dev_only: set[str]) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for key in new_keys:
        vuln = current[key]
        pkg_norm = vuln["pkg"].lower().replace("_", "-")
        if pkg_norm in dev_only:
            verdict = {"reachable": False, "confidence": "high",
                       "note": "dev-only dependency", "source": "dev-filter"}
            log(f"  {key} -> dev-only, skipping opencode")
        else:
            log(f"  {key} -> asking opencode...")
            verdict = opencode_reach_check(project_root, entry_points, model, vuln)
        results[key] = verdict
    return results


def merge_state(prev: dict, current: dict[str, dict],
                new_verdicts: dict[str, dict], ts: str) -> dict:
    old = (prev or {}).get("seen") or {}
    seen: dict[str, dict] = {}
    for key, value in current.items():
        entry = dict(old.get(key, {"first_seen": ts}))
        entry.update(new_verdicts.get(key, {}))
        entry["last_seen"] = ts
        entry["fix_versions"] = value["fix_versions"]
        seen[key] = entry
    return {"last_run": ts, "seen": seen}


def format_summary(project: str, reachable_results: dict[str, dict],
                   current: dict[str, dict]) -> str:
    n = len(reachable_results)
    plural = "" if n == 1 else "s"
    lines = [f"{project}: {n} new reachable CVE{plural}", ""]
    for key, verdict in reachable_results.items():
        d = current[key]
        conf = verdict.get("confidence") or "?"
        lines.append(f"{d['pkg']}=={d['ver']}  {d['id']}  ({conf})")
        fixes = d["fix_versions"]
        lines.append(f"  fix: {', '.join(fixes) if fixes else 'none yet'}")
        lines.append(f"  note: {verdict.get('note') or ''}")
        lines.append("")
    return "\n".join(lines)


def pushover_notify(title: str, message: str) -> None:
    user = os.environ.get("PUSHOVER_USER_KEY")
    app = os.environ.get("PUSHOVER_APP_KEY")
    if not user or not app:
        log("PUSHOVER_USER_KEY/APP_KEY not set; skipping Pushover.")
        return
    body_bytes = message.encode("utf-8")[:950]
    body = body_bytes.decode("utf-8", errors="ignore")
    data = urllib.parse.urlencode({
        "token": app,
        "user": user,
        "title": title,
        "priority": "1",
        "message": body,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.pushover.net/1/messages.json",
        data=data, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        log(f"Pushover delivery failed: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notify", action="store_true",
                        help="Deliver Pushover alert when a reachable CVE is found.")
    args = parser.parse_args()

    project = _require_env("SCAN_PROJECT")
    entry_points = _require_env("SCAN_ENTRY_POINTS")
    model = os.environ.get("SCAN_MODEL") or "z-ai/glm-5.1"
    notification_title = (
        os.environ.get("SCAN_NOTIFICATION_TITLE")
        or f"{project}: new reachable CVE"
    )

    project_root = pathlib.Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    )
    cache_dir = pathlib.Path(
        os.environ.get("STATE_DIR") or pathlib.Path.home() / ".cache" / "security-scan-ci"
    )
    state_file = cache_dir / f"{project}.json"

    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not state_file.exists() or state_file.stat().st_size == 0:
        atomic_write_json(state_file, {"last_run": None, "seen": {}})

    try:
        prev_state = json.loads(state_file.read_text())
    except json.JSONDecodeError:
        prev_state = {"last_run": None, "seen": {}}

    try:
        audit_data = run_pip_audit()
    except ScannerError as e:
        log(str(e))
        return 2

    current = extract_current_vulns(audit_data)
    ts = utcnow()

    if not current:
        atomic_write_json(state_file, {"last_run": ts, "seen": {}})
        log("pip-audit found 0 vulns; state reset.")
        return 0

    new_keys = compute_diff(current, prev_state)
    log(f"pip-audit found {len(current)} total vuln(s); {len(new_keys)} new since last run.")

    dev_only = dev_only_packages(project_root)
    new_verdicts = verify_reachability(
        project_root, entry_points, model, current, new_keys, dev_only,
    )

    next_state = merge_state(prev_state, current, new_verdicts, ts)
    atomic_write_json(state_file, next_state)

    reachable = {k: v for k, v in new_verdicts.items() if v.get("reachable")}
    if not reachable:
        if new_keys:
            log(f"{len(new_keys)} new vuln(s) this run, 0 reachable. Summary:")
            for k, v in new_verdicts.items():
                src = v.get("source") or "?"
                note = v.get("note") or ""
                log(f"  {k}\treachable={v.get('reachable')}\t{src}\t{note}")
        return 0

    summary = format_summary(project, reachable, current)
    print(summary)
    if args.notify:
        pushover_notify(notification_title, summary)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ScannerError as e:
        log(str(e))
        sys.exit(2)
