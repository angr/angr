#!/bin/bash

auth_token=$(gh auth token)

# Full corpus is: gh_path=cgc-challenges
# The Estadio challenge binaries were chosen chiefly for their lower run-time
# in angr. With the _patched versions, this is 6 binaries.
corpus_path="cgc-challenges/windows-build/challenges/Estadio;cgc-challenges/linux-build64/challenges/Estadio;cgc-challenges/linux-build/challenges/Estadio"
corpus_base_branch=main

if [[ -n "$1" ]]; then
    if [[ "$1" == "one" ]]; then
        corpus_path="one"
        corpus_base_branch=main-plus
    else
        echo "$0: unknown profile name '$1'; currently just 'one' is supported (or no argument to use 'angr:main')."
        exit 1
    fi
fi

# For now we always target the master branch of angr.
angr_base_branch=master
angr_local_branch="$(git rev-parse --abbrev-ref HEAD)"

if [[ -z "$angr_local_branch" ]]; then
   echo "$0: could not determine local git branch"
   exit 2
fi

if [[ "$angr_local_branch" == "main" ]]; then
   echo "$0: refusing to use 'main' as local git branch"
   exit 3
fi

echo "Using angr base branch '$angr_base_branch'."
echo "Using angr local branch '$angr_local_branch'."
echo "Using corpus base branch '$corpus_base_branch'."
echo "Using binary/snapshot corpus path '$corpus_path'."

cat > pr.event <<EOF
{
  "pull_request": {
    "head": {
      "ref": "$angr_local_branch"
    },
    "base": {
      "ref": "$angr_base_branch"
    }
  }
}
EOF

echo "pr.event:"
cat pr.event

echo "Running 'gh act ...'..."
gh act \
   -W ./.github/workflows/corpus_test.yml \
   -s GITHUB_TOKEN=$auth_token \
   -s CORPUS_ACCESS_TOKEN=$auth_token \
   -s SNAPSHOTS_PAT=$auth_token \
   --var CORPUS_GITHUB_OWNER=project-purcellville \
   --var CORPUS_GITHUB_REPO=direct-file-store-0000 \
   --var CORPUS_GITHUB_BRANCH="$corpus_base_branch" \
   --var CORPUS_GITHUB_PATH="$corpus_path" \
   --var SNAPSHOT_GITHUB_OWNER=project-purcellville \
   --var SNAPSHOT_GITHUB_REPO=snapshots-0000 \
   --var SNAPSHOT_GITHUB_BRANCH="$corpus_base_branch" \
   --eventpath pr.event \
   -v \
   pull_request
