#!/usr/bin/env python3
"""Passive, mechanically quarantined maintenance detector for usque.

The detector never makes a fresh update actionable. Each exact candidate is first
recorded as a non-actionable GitHub issue. Only after the same fingerprint has
remained continuously visible for QUARANTINE_HOURS does the detector create an
automation-queue issue for the maintenance sweep.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["GH_TOKEN"]
QUARANTINE_HOURS = int(os.environ.get("QUARANTINE_HOURS", "72"))
API = "https://api.github.com"
ROOT = Path(__file__).resolve().parents[2]

LABELS = {
    "automation:quarantine": ("6e7781", "Candidate observed but not yet old enough to act on"),
    "automation:dependency": ("1d76db", "Go dependency update queued automatically"),
    "automation:go-release": ("8250df", "Stable Go update queued automatically"),
    "automation:tooling": ("fbca04", "CI/release tooling update queued automatically"),
    "automation:maintenance-error": ("d73a4a", "Passive maintenance detector needs repair"),
}


def api(method: str, path: str, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codeandsolder-usque-maintenance-detector/1.0",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"GitHub API {method} {path} failed: {exc.code}: {body}") from exc


def ensure_labels() -> None:
    existing = {x["name"] for x in api("GET", f"/repos/{REPO}/labels?per_page=100")}
    for name, (color, description) in LABELS.items():
        if name in existing:
            api(
                "PATCH",
                f"/repos/{REPO}/labels/{urllib.parse.quote(name, safe='')}",
                {"color": color, "description": description},
            )
        else:
            api(
                "POST",
                f"/repos/{REPO}/labels",
                {"name": name, "color": color, "description": description},
            )


def open_issues(label: str | None = None) -> list[dict]:
    out = []
    page = 1
    while True:
        query = {"state": "open", "per_page": 100, "page": page}
        if label:
            query["labels"] = label
        path = f"/repos/{REPO}/issues?" + urllib.parse.urlencode(query)
        batch = [x for x in api("GET", path) if "pull_request" not in x]
        out.extend(batch)
        if len(batch) < 100:
            return out
        page += 1


def close_issue(number: int, comment: str | None = None) -> None:
    if comment:
        api("POST", f"/repos/{REPO}/issues/{number}/comments", {"body": comment})
    api("PATCH", f"/repos/{REPO}/issues/{number}", {"state": "closed", "state_reason": "completed"})


def marker(kind: str) -> str:
    return f"<!-- maintenance-kind:{kind} -->"


def fp_marker(fingerprint: str) -> str:
    return f"<!-- maintenance-fingerprint:{fingerprint} -->"


def issues_for_kind(label: str, kind: str) -> list[dict]:
    needle = marker(kind)
    return [x for x in open_issues(label) if needle in (x.get("body") or "")]


def quarantine_body(kind: str, fingerprint: str, summary: str) -> str:
    return f"""<!-- maintenance-quarantine -->
{marker(kind)}
{fp_marker(fingerprint)}

This exact maintenance candidate is in the **{QUARANTINE_HOURS}-hour mechanical quarantine**.

It becomes eligible only if this issue remains open with the same fingerprint for the full quarantine period. If the resolved candidate changes, the detector closes this state issue and starts a new timer.

{summary}

This issue is non-actionable quarantine state. The maintenance sweep must ignore it.
"""


def gate(kind: str, fingerprint: str, summary: str) -> bool:
    candidates = issues_for_kind("automation:quarantine", kind)
    same = [x for x in candidates if fp_marker(fingerprint) in (x.get("body") or "")]

    for issue in candidates:
        if issue not in same:
            close_issue(
                issue["number"],
                "Candidate changed before the quarantine expired; restarting the timer for the new exact candidate.",
            )

    if not same:
        api(
            "POST",
            f"/repos/{REPO}/issues",
            {
                "title": f"quarantine: {kind}",
                "labels": ["automation:quarantine"],
                "body": quarantine_body(kind, fingerprint, summary),
            },
        )
        print(f"{kind}: first sighting of {fingerprint}; quarantined")
        return False

    issue = min(same, key=lambda x: x["created_at"])
    for duplicate in same:
        if duplicate["number"] != issue["number"]:
            close_issue(duplicate["number"], "Duplicate quarantine state; keeping the oldest timer.")

    desired = quarantine_body(kind, fingerprint, summary)
    if (issue.get("body") or "") != desired:
        api("PATCH", f"/repos/{REPO}/issues/{issue['number']}", {"body": desired})

    created = dt.datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
    age = dt.datetime.now(dt.timezone.utc) - created
    eligible = age >= dt.timedelta(hours=QUARANTINE_HOURS)
    print(f"{kind}: candidate age {age}; eligible={eligible}")
    return eligible


def clear_kind(kind: str, queue_label: str) -> None:
    for issue in issues_for_kind("automation:quarantine", kind):
        close_issue(issue["number"], "No update candidate remains; clearing quarantine state.")
    for issue in issues_for_kind(queue_label, kind):
        close_issue(issue["number"], "No update candidate remains.")


def manage_queue(
    *,
    kind: str,
    queue_label: str,
    queue_marker: str,
    title: str,
    fingerprint: str,
    body: str,
    eligible: bool,
) -> None:
    current = issues_for_kind(queue_label, kind)
    if not eligible:
        for issue in current:
            close_issue(
                issue["number"],
                "The detector now sees a different or still-quarantined candidate; this actionable issue is stale.",
            )
        return

    full_body = f"""{marker(kind)}
{fp_marker(fingerprint)}
<!-- automation-queue:{queue_marker} -->

{body}

**Mechanical quarantine:** this exact candidate fingerprint was continuously observed for at least {QUARANTINE_HOURS} hours before this issue became actionable. Apply the exact candidate described here; do not substitute newer versions during implementation.
"""
    matching = [x for x in current if fp_marker(fingerprint) in (x.get("body") or "")]
    for issue in current:
        if issue not in matching:
            close_issue(issue["number"], "Superseded by a different detector-approved candidate.")
    if matching:
        issue = matching[0]
        api("PATCH", f"/repos/{REPO}/issues/{issue['number']}", {"title": title, "body": full_body})
        for duplicate in matching[1:]:
            close_issue(duplicate["number"], "Duplicate actionable maintenance issue.")
    else:
        api(
            "POST",
            f"/repos/{REPO}/issues",
            {"title": title, "labels": [queue_label], "body": full_body},
        )


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def module_map() -> dict[str, str]:
    out = run(
        "go",
        "list",
        "-m",
        "-f",
        "{{.Path}}\t{{.Version}}{{if .Replace}} => {{.Replace.Path}} {{.Replace.Version}}{{end}}",
        "all",
    ).stdout
    result = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        path, _, value = line.partition("\t")
        result[path] = value
    return result


def read_holds() -> list[tuple[str, str, str]]:
    path = ROOT / ".github" / "maintenance-holds.txt"
    holds = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        value, _, comment = line.partition("#")
        parts = value.split()
        if len(parts) != 2:
            raise RuntimeError(f"invalid maintenance hold line: {raw!r}")
        holds.append((parts[0], parts[1], comment.strip()))
    return holds


def detect_modules():
    before = module_map()
    proc = run("go", "get", "-u", "./...", check=False)
    if proc.returncode:
        raise RuntimeError("go get -u ./... failed:\n" + proc.stdout[-12000:])

    for module, version, _reason in read_holds():
        proc = run("go", "get", f"{module}@{version}", check=False)
        if proc.returncode:
            raise RuntimeError(f"failed to reapply maintenance hold {module}@{version}:\n{proc.stdout[-8000:]}")

    proc = run("go", "mod", "tidy", check=False)
    if proc.returncode:
        raise RuntimeError("go mod tidy failed:\n" + proc.stdout[-12000:])

    changed = run("git", "diff", "--quiet", "--", "go.mod", "go.sum", check=False).returncode != 0
    if not changed:
        run("git", "reset", "--hard", "HEAD")
        return None

    after = module_map()
    changes = []
    for path in sorted(set(before) | set(after)):
        if before.get(path) != after.get(path):
            changes.append((path, before.get(path, "(none)"), after.get(path, "(removed)")))

    go_mod = (ROOT / "go.mod").read_bytes()
    go_sum = (ROOT / "go.sum").read_bytes()
    fingerprint = hashlib.sha256(go_mod + b"\0" + go_sum).hexdigest()
    diff = run("git", "diff", "--", "go.mod").stdout
    run("git", "reset", "--hard", "HEAD")

    lines = "\n".join(f"- `{p}`: `{old}` → `{new}`" for p, old, new in changes)
    hold_lines = "\n".join(
        f"- `{m}@{v}` — {reason}" for m, v, reason in read_holds()
    )
    summary = f"""Candidate module changes:
{lines}

Configured compatibility holds reapplied before fingerprinting:
{hold_lines or "- none"}"""
    body = f"""The detector resolved this exact Go module update set:

{lines}

The resulting `go.mod` change is:

```diff
{diff}
```

Reproduce these exact versions, run `go mod tidy`, review noteworthy release notes/API changes, and run the full CI/release validation. The fingerprint also covers the resulting `go.sum`.

Current mechanical compatibility holds:
{hold_lines or "- none"}"""
    return fingerprint, summary, body


def detect_go_release():
    current = next(
        line.split()[1]
        for line in (ROOT / "go.mod").read_text().splitlines()
        if line.startswith("go ")
    )
    with urllib.request.urlopen("https://go.dev/VERSION?m=text", timeout=30) as response:
        latest = response.read().decode().splitlines()[0].removeprefix("go")
    if latest == current:
        return None
    fingerprint = hashlib.sha256(latest.encode()).hexdigest()
    summary = f"Go stable candidate: `{current}` → `{latest}`"
    body = f"""Go `{latest}` has remained the exact detector candidate for the full quarantine period; the repository currently declares `{current}`.

Perform the full Go-release refresh: read the official release and point-release notes, update the `go` directive/tooling as appropriate, review language/library/compiler/runtime/module/vet/platform changes, remove obsolete workarounds where justified, then run the full CI and release cross-build validation."""
    return fingerprint, summary, body, latest


def github_latest(repo: str) -> str:
    payload = api("GET", f"/repos/{repo}/releases/latest")
    return payload["tag_name"]


def file_text(path: str) -> str:
    return (ROOT / path).read_text()


def detect_tooling():
    updates = []
    workflow_files = [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/workflows/maintenance-queue.yml",
    ]

    action_specs = [
        ("actions/checkout", workflow_files),
        ("actions/setup-go", workflow_files),
        ("golangci/golangci-lint-action", [".github/workflows/ci.yml"]),
        ("goreleaser/goreleaser-action", [".github/workflows/release.yml"]),
    ]
    for repo, files in action_specs:
        latest = github_latest(repo)
        pattern = re.compile(rf"{re.escape(repo)}@([^\s]+)")
        found = sorted({m.group(1) for f in files for m in pattern.finditer(file_text(f))})
        if found != [latest]:
            updates.append({"pin": repo, "current": found, "latest": latest})

    ci = file_text(".github/workflows/ci.yml")
    latest_lint = github_latest("golangci/golangci-lint")
    match = re.search(r"version:\s*(v[^\s]+)", ci)
    current_lint = match.group(1) if match else None
    if current_lint != latest_lint:
        updates.append({"pin": "golangci-lint", "current": current_lint, "latest": latest_lint})

    release = file_text(".github/workflows/release.yml")
    latest_goreleaser = github_latest("goreleaser/goreleaser")
    match = re.search(r"distribution:\s*goreleaser\s*\n\s*version:\s*([^\s]+)", release)
    current_goreleaser = match.group(1).strip("'\"") if match else None
    if current_goreleaser != latest_goreleaser:
        updates.append({"pin": "goreleaser", "current": current_goreleaser, "latest": latest_goreleaser})

    req = urllib.request.Request(
        "https://www.wintun.net/",
        headers={"User-Agent": "codeandsolder-usque-maintenance-detector/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        html = response.read().decode()
    versions = re.findall(r"wintun-([0-9]+(?:\.[0-9]+)+)\.zip", html)
    if not versions:
        raise RuntimeError("could not determine current Wintun version")
    latest_wintun = max(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    version_match = re.search(r'WINTUN_VERSION:\s*"([^"]+)"', release)
    sha_match = re.search(r'WINTUN_SHA256:\s*"([0-9a-f]{64})"', release)
    current_wintun = version_match.group(1) if version_match else None
    current_sha = sha_match.group(1) if sha_match else None

    archive = urllib.request.Request(
        f"https://www.wintun.net/builds/wintun-{latest_wintun}.zip",
        headers={"User-Agent": "codeandsolder-usque-maintenance-detector/1.0"},
    )
    digest = hashlib.sha256()
    with urllib.request.urlopen(archive, timeout=30) as response:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
    latest_sha = digest.hexdigest()

    if current_wintun != latest_wintun or current_sha != latest_sha:
        updates.append(
            {
                "pin": "Wintun",
                "current": {"version": current_wintun, "sha256": current_sha},
                "latest": {"version": latest_wintun, "sha256": latest_sha},
            }
        )

    if not updates:
        return None

    canonical = json.dumps(updates, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
    details = "\n".join(
        f"- `{u['pin']}`: `{json.dumps(u['current'], sort_keys=True)}` → `{json.dumps(u['latest'], sort_keys=True)}`"
        for u in updates
    )
    summary = "Pinned tooling candidate:\n" + details
    body = f"""The following exact CI/release-tooling candidate set survived quarantine:

{details}

Update exactly these pins together. Review migration notes for major-version changes, keep exact action/tool versions, run the full CI suite and `goreleaser check`, and verify release-only payload handling. For Wintun, use the detector-provided SHA-256 rather than independently selecting a newer archive."""
    return fingerprint, summary, body


def error_issue(kind: str, exc: BaseException) -> None:
    error_marker = f"<!-- maintenance-error:{kind} -->"
    body = f"""{error_marker}
<!-- automation-queue:maintenance-error -->

The passive maintenance detector failed while checking **{kind}**.

```text
{type(exc).__name__}: {exc}
```

Repair the detector or repository state so mechanically quarantined update detection resumes.
"""
    current = [
        x
        for x in open_issues("automation:maintenance-error")
        if error_marker in (x.get("body") or "")
    ]
    if current:
        api("PATCH", f"/repos/{REPO}/issues/{current[0]['number']}", {"body": body})
    else:
        api(
            "POST",
            f"/repos/{REPO}/issues",
            {
                "title": f"maintenance detector: {kind} failed",
                "labels": ["automation:maintenance-error"],
                "body": body,
            },
        )


def clear_error(kind: str) -> None:
    error_marker = f"<!-- maintenance-error:{kind} -->"
    for issue in open_issues("automation:maintenance-error"):
        if error_marker in (issue.get("body") or ""):
            close_issue(issue["number"], "Detector recovered.")


def process(kind: str, label: str, queue_marker: str, title: str, detector) -> bool:
    try:
        candidate = detector()
        clear_error(kind)
        if candidate is None:
            clear_kind(kind, label)
            print(f"{kind}: no update candidate")
            return True

        fingerprint, summary, body, *_ = candidate
        eligible = gate(kind, fingerprint, summary)
        manage_queue(
            kind=kind,
            queue_label=label,
            queue_marker=queue_marker,
            title=title,
            fingerprint=fingerprint,
            body=body,
            eligible=eligible,
        )
        return True
    except BaseException as exc:
        try:
            run("git", "reset", "--hard", "HEAD", check=False)
        finally:
            error_issue(kind, exc)
        print(f"{kind}: detector failed: {exc}", file=sys.stderr)
        return False


def main() -> int:
    os.chdir(ROOT)
    ensure_labels()
    ok = True
    ok &= process(
        "go-modules",
        "automation:dependency",
        "go-dependencies",
        "deps: refresh Go module graph",
        detect_modules,
    )
    ok &= process(
        "go-stable",
        "automation:go-release",
        "go-release",
        "Go stable: full best-practices refresh",
        detect_go_release,
    )
    ok &= process(
        "tooling",
        "automation:tooling",
        "tooling",
        "maintenance: update pinned tooling",
        detect_tooling,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
