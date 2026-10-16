#!/usr/bin/env bash
# One-shot: push this folder to Breead1337/ws-cache-9e41, switch Pages to "GitHub Actions", start the first build.
# Run from this folder:  bash publish.sh
set -euo pipefail
cd "$(dirname "$0")"
REPO=Breead1337/ws-cache-9e41
TOKEN=${GH_TOKEN:-$(git -C ../../olcvpn-client remote get-url origin | sed -E 's#.*:([^@]+)@.*#\1#')}

rm -rf out out_test
[ -d .git ] || git init -q -b main            # own repo: the parent folder is another git repo
git config user.name bot
git config user.email bot@users.noreply.github.com
git add -A
git commit -q -m init || true
git push -q "https://Breead1337:${TOKEN}@github.com/${REPO}.git" main
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/${REPO}.git"

api() { curl -s -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" "$@"; }
api -X POST "https://api.github.com/repos/${REPO}/pages" -d '{"build_type":"workflow"}' -o /dev/null -w "pages http=%{http_code}\n"
api -X POST "https://api.github.com/repos/${REPO}/actions/workflows/collect.yml/dispatches" -d '{"ref":"main"}' -w "dispatch http=%{http_code}\n"
echo "build started: https://github.com/${REPO}/actions"
