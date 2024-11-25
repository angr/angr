#!/usr/bin/env bash

set -eo pipefail

help() {
  SCRIPT_NAME="$(basename "$0")"
  cat <<ANGR
Usage: $SCRIPT_NAME (-R|--repo) <repo> [OPTIONS]

  Fetches file paths from a given GitHub repository based on a tree SHA.

  This method of remote enumeration is used for quick lookup and access of files
  in repositories like the file store that may have a very large number of files.

Examples:
  $SCRIPT_NAME -R project-purcellville/direct-file-store-0000 -t "\$(gh auth token)"

  $SCRIPT_NAME -R project-purcellville/direct-file-store-0000 --branch pr-404 --path "stable/*/linux-build/"

  $SCRIPT_NAME -R project-purcellville/direct-file-store-0000 --branch pr-404 --path "*.dll"

Options:
  -h, --help

      Show this help message and exit

  -p <path>, --path <path>

      The leading file path patterns to include from the repository. If the
      pattern is a directory, all files under the tree will be included. If
      omitted, the script will enumerate from the repository root path. Repeat
      to enumerate multiple file paths.

  -s <sha>, --sha <sha>

      The optional SHA of the tree to fetch files from.
      Repeat to enumerate multiple trees.

  --with-sha

      Return the list of remote files with their git SHA values.

GitHub Options:

  -b <branch>, --branch <branch>

      The GitHub repository branch or ref to enumerate.

  -R <repo>, --repo <repo>

      The GitHub repository to enumerate using the OWNER/REPO format.

  -t <token>, --token <token>

      A GitHub token with access permissions. This can also be specified via the
      GITHUB_TOKEN environment variable.
ANGR
  exit 1
}

declare -a FILEPATH
declare -a STARTPATTERN
declare -a SHA
WITH_SHA=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -b|--branch)
        BRANCH="$2"
        shift 2
        ;;
      -h|--help)
        help
        ;;
      -p|--path)
        STARTPATTERN+=("$2")
        shift 2
        ;;
      -R|--repo)
        REPO="$2"
        shift 2
        ;;
      -s|--sha)
        SHA+=("$2")
        shift 2
        ;;
      -t|--token)
        GITHUB_TOKEN="$2"
        shift 2
        ;;
      --with-sha)
        WITH_SHA="1"
        shift
        ;;
      *)
        echo "Unknown option: $1"
        help
        ;;
    esac
  done
}

parse_args "$@"

if [[ -z "${REPO}" ]]; then
  echo "ERROR: <repo> not provided"
  echo
  help
fi

fetch_tree() {
  local path="${1}"
  local response
  response="$(curl \
    --show-error \
    --silent \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/${REPO}/contents/${path}?ref=${BRANCH:-HEAD}")"
  if ! [[ "$(echo "${response}" | jq -r 'if type == "array" then 0 else .status end')" -eq 0 ]]; then
    echo "${response}" | jq
    exit 1
  fi

  while read -r item; do
    case "$(echo "$item" | jq -r '.type')" in
      dir)
        SHA+=("$(echo "$item" | jq -r '.sha + " " + .name')")
        ;;
      file)
        FILEPATH+=("$(echo "$item" | jq -r '.name')")
        ;;
    esac
  done < <(echo "${response}" | jq -c '.[] | {name, sha, type}')
}

fetch_tree_by_sha() {
  local sha="${1}"
  local prefix="${2}"
  local response
  response="$(curl \
    --show-error \
    --silent \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com/repos/${REPO}/git/trees/${sha}?recursive=1")"
  if ! [[ "$(echo "${response}" | jq -r 'if type == "array" then 0 else .status end')" -eq 0 ]]; then
    echo "${response}" | jq
    exit 1
  fi

  # shellcheck disable=SC2016
  if [[ -n "${WITH_SHA}" ]]; then
    jq_program='.tree[] | select(.type == "blob") | $prefix + "/" + .path + "," + .sha'
  else
    jq_program='.tree[] | select(.type == "blob") | $prefix + "/" + .path'
  fi

  while read -r item; do
    FILEPATH+=("${item}")
  done < <(echo "${response}" | jq -r --arg prefix "${prefix}" "${jq_program}")
}

# If SHAs are not provided, get them from the repo.
if [[ ${#SHA[@]} -eq 0 ]]; then
  fetch_tree ""
fi

# For each provided SHA, recursively enumerate the files.
for shapair in "${SHA[@]}"; do
  sha="$(echo "${shapair}" | awk '{print $1}')"
  path="$(echo "${shapair}" | awk '{print $2}')"
  fetch_tree_by_sha "${sha}" "${path}"
done

# For each collected file path, print it only if it matches one of the provided
# path patterns. If none are provided, match an empty prefix to include all
# files.
if [[ ${#STARTPATTERN[@]} -eq 0 ]]; then
  STARTPATTERN+=("")
fi

for path in "${FILEPATH[@]}"; do
  for pattern in "${STARTPATTERN[@]}"; do
    if [[ "$path" == $pattern* ]]; then
      echo "${path}"
      break
    fi
  done
done
