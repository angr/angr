#!/usr/bin/env bash

set -euo pipefail
shopt -s lastpipe

help() {
  SCRIPT_NAME="$(basename "$0")"
  cat <<ANGR
Usage: $SCRIPT_NAME <local_file> <remote_path> [OPTIONS]

  Push a file to the remote GitHub repository. Overwriting if necessary.

Examples:
  $SCRIPT_NAME -R project-purcellville/angr -H pr-404 -t "\$(gh auth token)" \
    <local_file> <remote_path>

Options:
  -h, --help

      Show this help message and exit

GitHub Options:

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

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h|--help)
        help
        ;;
      -H|--head-ref)
        REF_HEAD="$2"
        shift 2
        ;;
      -R|--repo)
        REPO="$2"
        shift 2
        ;;
      -t|--token)
        export GH_TOKEN="$2"
        shift 2
        ;;
      -|--)
        echo "Unknown option: $1"
        help
        ;;
      *)
        REST+=("$1")
        shift 1
        ;;
    esac
  done
}

parse_args "$@"

if [[ "${#REST[@]}" -ne 2 ]]; then
  echo "ERROR: need 2 snapshots"
  echo
  help
fi

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

LOCAL_FILE="${REST[0]}"
LOCAL_SHA="$(git hash-object "${LOCAL_FILE}")"
REMOTE_PATH="${REST[1]}"
"${SCRIPT_DIR}/gh_ls.sh" \
  -R "${REPO}" \
  -t "${GH_TOKEN}" \
  -b "${REF_HEAD}" \
  -p "${REMOTE_PATH}" \
  --with-sha | \
awk -F, '{print $NF}' | \
read -r REMOTE_SHA

# NB: This SHA_OPTION must be provided if updating an existing file.
declare -a SHA_OPTION
if [[ -n "${REMOTE_SHA}" ]]; then
  SHA_OPTION=(-f sha="${REMOTE_SHA}")
fi

printf "Local (%s:%s), Remote (%s:%s)\n" \
  "${LOCAL_FILE}" "${LOCAL_SHA}" \
  "${REMOTE_PATH}" "${REMOTE_SHA}" 2>&1

# shellcheck disable=SC2068
gh api "/repos/${REPO}/contents/${REMOTE_PATH}" \
   -X PUT \
   -H "Accept: application/vnd.github.v3+json" \
   -f message="update file contents [${REMOTE_PATH}]" \
   -f "committer[name]=github-actions[bot]" \
   -f "committer[email]=github-actions[bot]@users.noreply.github.com" \
   -f content="$(base64 < "${LOCAL_FILE}")" \
   -f branch="${REF_HEAD}" \
   ${SHA_OPTION[@]} | \
jq -c '.' | \
read -r HTTP_RESPONSE

HTTP_STATUS="$(jq -r .status <<< "$HTTP_RESPONSE")"

EX_OK=0
EX_GENERIC=1
EX_TEMPFAIL=75
EX_NOTFOUND=127

case $HTTP_STATUS in
  # Successfully created a file.
  200) exit $EX_OK ;;

  # GitHub rate limits are hourly limits. Short-circuit.
  #
  # gh: API rate limit exceeded for user ID <id>. If you reach out to GitHub
  #     Support for help, please include the request ID <id> and timestamp
  #     2024-12-03 UTC. (HTTP 403)
  403 | 429) exit $EX_NOTFOUND ;;

  # Branch does not exist. Short-circuit.
  #
  # gh: Branch feat/multisimplifier_replacement not found (HTTP 404)
  404) exit $EX_NOTFOUND ;;

  # Conflict: File does not match. Signal to retry. This script will get invoked
  # again, at which time, the updated file SHA should be retrieved.
  #
  # gh: snapshots/stable/cgc-challenges/linux-build64/BudgIT.json.txt does not
  #     match a07355019d18e4c9fa09a2150379f6b0c48e257e (HTTP 409)
  409) exit $EX_TEMPFAIL ;;

  # gh: We couldn't respond to your request in time. Sorry about that. Please try
  #     resubmitting your request and contact us if the problem persists. (HTTP 504)
  504) exit $EX_TEMPFAIL ;;

  *) exit $EX_GENERIC ;;
esac
