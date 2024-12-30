#!/usr/bin/env bash

set -euo pipefail
shopt -s lastpipe
[[ -n "${DEBUG:-}" ]] && set -x

help() {
  SCRIPT_NAME="$(basename "$0")"
  cat <<ANGR
Usage: $SCRIPT_NAME (-R|--repo) <repo> [OPTIONS]

  Create a new branch in the remote GitHub repository.

Examples:
  $SCRIPT_NAME -R project-purcellville/angr -H pr-404 -t "\$(gh auth token)"

Options:
  -h, --help

      Show this help message and exit

GitHub Options:

  -b <ref>, --base-ref <ref>

      The name of the base repository ref to branch from. This defaults to HEAD.

  -H <ref>, --head-ref <ref>

      The name of the head repository ref to newly create.

  -R <repo>, --repo <repo>

      The GitHub repository to enumerate using the OWNER/REPO format.

  -t <token>, --token <token>

      A GitHub token with access permissions. This can also be specified via the
      GH_TOKEN environment variable.
ANGR
  exit 1
}

GH_TOKEN="${GH_TOKEN:-}"
REF_BASE=""
REF_HEAD=""
REPO=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
    -b | --base-ref)
      REF_BASE="${2}"
      shift 2
      ;;
    -h | --help)
      help
      ;;
    -H | --head-ref)
      REF_HEAD="$2"
      shift 2
      ;;
    -R | --repo)
      REPO="$2"
      shift 2
      ;;
    -t | --token)
      export GH_TOKEN="$2"
      shift 2
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

if [[ -z "${REF_HEAD}" ]]; then
  echo "ERROR: head <ref> not provided"
  echo
  help
fi

# Get the default branch for the repository.
if [[ -z "${REF_BASE}" ]]; then
  printf "Looking up default branch for repo: %s\n" "${REPO}" >&2
  gh api "/repos/${REPO}" \
    -X GET \
    -H "Accept: application/vnd.github.v3+json" |
    jq -r '.default_branch' |
    read -r REF_BASE || :
fi

# Get the sha value for the default branch.
SHA=""
gh api "/repos/${REPO}/git/refs/heads/${REF_BASE}" \
  -X GET \
  -H "Accept: application/vnd.github.v3+json" |
  jq -r .object.sha |
  read -r SHA || :

if [[ -z "${SHA}" ]]; then
  echo "ERROR: Could not lookup ref: '${REF_BASE}'" >&2
  exit 1
fi
printf "Found REF_BASE: %s %s\n" "${REF_BASE}" "${SHA}" >&2

# Check to see if the target branch already exists.
HTTP_RESPONSE=""
gh api "/repos/${REPO}/git/refs/heads/${REF_HEAD}" \
  -X GET \
  -H "Accept: application/vnd.github.v3+json" 2>/dev/null |
  jq -c '.' |
  read -r HTTP_RESPONSE || :

HTTP_STATUS="$(jq -r '.status // 200' <<<"$HTTP_RESPONSE")"

if [[ "${HTTP_STATUS}" = "404" ]]; then
  # Create the new ref.
  gh api "/repos/${REPO}/git/refs" \
    -X POST \
    -H "Accept: application/vnd.github.v3+json" \
    -f ref="refs/heads/${REF_HEAD}" \
    -f sha="${SHA}"
elif [[ "${HTTP_STATUS}" = "200" ]]; then
  echo "Ref already exists: '${REF_HEAD}'" >&2
else
  echo "ERROR: Unexpected error: ${HTTP_STATUS}" >&2
  exit 1
fi
