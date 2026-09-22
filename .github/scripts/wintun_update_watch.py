#!/usr/bin/env python3
"""Track the one dependency Renovate cannot safely manage for us: Wintun."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["GH_TOKEN"]
API = "https://api.github.com"
HOURS = 72


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
            "User-Agent": "codeandsolder-wintun-watch/1.0",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        body = response.read()
        return json.loads(body) if body else None


def open_issues(label: str) -> list[dict]:
    query = urllib.parse.urlencode({"state": "open", "labels": label, "per_page": 100})
    return [
        item
        for item in api("GET", f"/repos/{REPO}/issues?{query}")
        if "pull_request" not in item
    ]


def close(issue: dict, comment: str) -> None:
    api("POST", f"/repos/{REPO}/issues/{issue['number']}/comments", {"body": comment})
    api(
        "PATCH",
        f"/repos/{REPO}/issues/{issue['number']}",
        {"state": "closed", "state_reason": "completed"},
    )


def current_version() -> str:
    text = Path(".github/workflows/release.yml").read_text()
    match = re.search(r'WINTUN_VERSION:\s*"([^"]+)"', text)
    if not match:
        raise RuntimeError("WINTUN_VERSION not found in release workflow")
    return match.group(1)


def latest_version() -> str:
    req = urllib.request.Request(
        "https://www.wintun.net/",
        headers={"User-Agent": "codeandsolder-wintun-watch/1.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        html = response.read().decode()
    versions = re.findall(r"wintun-([0-9]+(?:\.[0-9]+)+)\.zip", html)
    if not versions:
        raise RuntimeError("could not determine latest Wintun version")
    return max(versions, key=lambda value: tuple(int(part) for part in value.split(".")))


def main() -> int:
    current = current_version()
    latest = latest_version()
    quarantine = open_issues("automation:quarantine")
    queued = open_issues("automation:dependency")

    qprefix = "<!-- wintun-candidate:"
    qmarker = f"<!-- wintun-candidate:{latest} -->"
    queue_marker = "<!-- automation-queue:wintun -->"

    relevant_quarantine = [i for i in quarantine if qprefix in (i.get("body") or "")]
    relevant_queue = [i for i in queued if queue_marker in (i.get("body") or "")]

    if latest == current:
        for issue in relevant_quarantine + relevant_queue:
            close(issue, f"Closed automatically: Wintun {current} is now current.")
        print(f"Wintun {current} is current.")
        return 0

    same = [i for i in relevant_quarantine if qmarker in (i.get("body") or "")]
    for issue in relevant_quarantine:
        if issue not in same:
            close(issue, f"Superseded by Wintun {latest}; restarting the 72-hour observation window.")
    for issue in relevant_queue:
        if qmarker not in (issue.get("body") or ""):
            close(issue, f"Superseded by Wintun {latest}.")

    if not same:
        body = f"""<!-- maintenance-quarantine -->
{qmarker}

Wintun **{latest}** is newer than the repository's **{current}**.

This is the first observation of this exact candidate. Do not update yet; the candidate becomes actionable after it has remained unchanged for {HOURS} hours.
"""
        api(
            "POST",
            f"/repos/{REPO}/issues",
            {
                "title": f"quarantine: Wintun {latest}",
                "labels": ["automation:quarantine"],
                "body": body,
            },
        )
        print(f"First observation of Wintun {latest}; quarantine started.")
        return 0

    oldest = min(same, key=lambda issue: issue["created_at"])
    created = dt.datetime.fromisoformat(oldest["created_at"].replace("Z", "+00:00"))
    age = dt.datetime.now(dt.timezone.utc) - created
    if age < dt.timedelta(hours=HOURS):
        print(f"Wintun {latest} has been stable for {age}; still quarantined.")
        return 0

    body = f"""{qmarker}
{queue_marker}

Wintun **{latest}** has remained the exact observed candidate for at least {HOURS} hours; the repository currently pins **{current}**.

Update WINTUN_VERSION to {latest}, download that exact archive, replace WINTUN_SHA256 with its SHA-256, and run the full release/CI validation. Do not substitute a newer candidate during this task.
"""
    existing = [i for i in relevant_queue if qmarker in (i.get("body") or "")]
    if existing:
        api(
            "PATCH",
            f"/repos/{REPO}/issues/{existing[0]['number']}",
            {"title": f"deps: update Wintun to {latest}", "body": body},
        )
    else:
        api(
            "POST",
            f"/repos/{REPO}/issues",
            {
                "title": f"deps: update Wintun to {latest}",
                "labels": ["automation:dependency"],
                "body": body,
            },
        )
    print(f"Wintun {latest} is actionable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
