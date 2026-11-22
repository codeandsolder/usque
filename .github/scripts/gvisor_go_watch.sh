#!/usr/bin/env bash
set -euo pipefail

module=gvisor.dev/gvisor
label=automation:gvisor-go
current="$(go list -m -json "$module")"
candidate="$(go list -m -json "$module@go")"
current_version="$(jq -er .Version <<< "$current")"
candidate_version="$(jq -er .Version <<< "$candidate")"
current_time="$(jq -er .Time <<< "$current")"
candidate_time="$(jq -er .Time <<< "$candidate")"

# The upstream default branch is Bazel source, not the published Go module.
# The Go branch is generated and contains the files required by go build.
# Never request a default-branch digest or silently downgrade a working pin.
gh label create "$label" --repo "$REPO" --color 1d76db \
  --description "Update gVisor from its generated Go module branch" --force
issue="$(gh issue list --repo "$REPO" --state open --label "$label" \
  --limit 1 --json number --jq '.[0].number // empty')"
if [[ "$candidate_version" == "$current_version" || "$candidate_time" < "$current_time" ]]; then
  if [[ -n "$issue" ]]; then
    gh issue close "$issue" --repo "$REPO" --comment "No newer generated Go module revision than the adopted $current_version."
  fi
  exit 0
fi

title="Update gVisor Go module to $candidate_version"
body="$(cat <<BODY
The generated [gVisor Go branch](https://github.com/google/gvisor/tree/go) has published a newer revision.

Current: \`$current_version\`
Candidate: \`$candidate_version\`

Update reproducibly with:

\`\`\`bash
go get gvisor.dev/gvisor@$candidate_version
go mod tidy
go mod verify
CGO_ENABLED=0 go build -trimpath ./...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go test ./...
\`\`\`

Open a normal dependency PR and require the existing CI. Do not use the upstream default branch: it is not a complete generated Go module.
BODY
)"
if [[ -n "$issue" ]]; then
  old="$(gh issue view "$issue" --repo "$REPO" --json title,body)"
  if [[ "$(jq -r .title <<< "$old")" != "$title" || "$(jq -r .body <<< "$old")" != "$body" ]]; then
    gh issue edit "$issue" --repo "$REPO" --title "$title" --body "$body"
  fi
else
  gh issue create --repo "$REPO" --title "$title" --body "$body" --label "$label"
fi
