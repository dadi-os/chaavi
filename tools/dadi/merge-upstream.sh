#!/usr/bin/env bash
# Merge a Vaultwarden release (or any upstream ref) into Chaavi and settle the conflicts that are
# always ours. The merge is left uncommitted: build it, run the tests, read the watch list, commit.
#
#   tools/dadi/merge-upstream.sh 1.37.5          # a release tag
#   tools/dadi/merge-upstream.sh upstream/main   # try upstream's tip without waiting for a tag
#
# Abort with `git merge --abort`.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
ref="${1:?usage: tools/dadi/merge-upstream.sh <upstream tag or ref>}"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "The working tree has changes; commit or stash them first." >&2
  exit 1
fi

# Upstream workflows dadi removed (they publish to Vaultwarden's own registry or lint files this
# fork does not own). An upstream edit to one is a modify/delete conflict; the answer is always delete.
removed_upstream_files=(
  .github/workflows/release.yml
  .github/workflows/releasecache-cleanup.yml
  .github/workflows/trivy.yml
  .github/workflows/typos.yml
  .github/workflows/zizmor.yml
)
# What src/dadi relies on. A change here is where a merge can break Chaavi without a conflict.
watch_list=(
  src/api/core/ciphers.rs src/db/models/cipher.rs src/db/models/folder.rs src/db/models/user.rs
  src/db/models/device.rs src/api/notifications.rs src/auth.rs src/crypto.rs src/main.rs
  src/api/core/mod.rs src/db/mod.rs
)

git config merge.ours.driver true
git config rerere.enabled true
git remote get-url upstream >/dev/null 2>&1 || git remote add upstream https://github.com/dani-garcia/vaultwarden.git
git fetch -q --tags upstream
git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || { echo "No such ref: $ref" >&2; exit 1; }

echo "== upstream commits to take"
git log --oneline "HEAD..$ref" | head -40

merged=0
git merge --no-commit --no-ff "$ref" >/dev/null 2>&1 && merged=1 || true

for path in "${removed_upstream_files[@]}"; do
  if git ls-files --unmerged -- "$path" | grep -q .; then
    git rm -qf -- "$path"
  fi
done

# Upstream's README lives on as docs/vaultwarden-README.md; README.md is dadi's.
if git cat-file -e "$ref:README.md" 2>/dev/null; then
  git show "$ref:README.md" > docs/vaultwarden-README.md
  git add docs/vaultwarden-README.md
fi

echo
conflicts=$(git diff --name-only --diff-filter=U)
if [ -n "$conflicts" ]; then
  echo "== conflicts left for you (resolve, then git add):"
  echo "$conflicts" | sed 's/^/   /'
else
  echo "== no conflicts"
fi

echo
echo "== watch list: upstream changes to files src/dadi depends on"
changed=$(git diff --stat "$(git merge-base HEAD "$ref")" "$ref" -- "${watch_list[@]}" | tail -n +1)
if [ -n "$changed" ]; then echo "$changed"; else echo "   none"; fi

echo
echo "== new cipher types? (src/dadi supports types 1-8; upstream's write path accepts:)"
git show "$ref:src/api/core/ciphers.rs" | grep -nE '^\s+[0-9]+ => data\.' | sed 's/^/   /' || true

cat <<'MSG'

Next:
  cargo test --features sqlite 'dadi::' && cargo clippy --features sqlite --tests
  (cd dadi-tests && npm ci && ./serve-local.sh &)   # then the interop suite, see README
  git commit        # message: which release, anything dadi had to change
MSG
exit 0
