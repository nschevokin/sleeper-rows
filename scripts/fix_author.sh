#!/usr/bin/env bash
# Rewrite every commit's author and committer to you, so GitHub links them to your profile.
# Usage: scripts/fix_author.sh "Nikita Chevokin" "nikchevokin@outlook.com"
# Run it once on a fresh clone/copy BEFORE the first push. It rewrites history of the current branch.
set -euo pipefail
name="${1:?name}"; email="${2:?email}"
git filter-branch -f --env-filter "
export GIT_AUTHOR_NAME='$name'; export GIT_AUTHOR_EMAIL='$email'
export GIT_COMMITTER_NAME='$name'; export GIT_COMMITTER_EMAIL='$email'
" -- --all
git config user.name "$name"; git config user.email "$email"
git log --format='%an <%ae>' | sort -u
