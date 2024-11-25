#!/usr/bin/env bash

set -o pipefail

help() {
  SCRIPT_NAME="$(basename "$0")"
  cat <<ANGR
Usage: $SCRIPT_NAME (<remote_path>) | (<local_snapshot1> <local_snapshot2>) [OPTIONS]

  Compares 1-to-1 decompilation snapshots for a particular file.

Examples:
  $SCRIPT_NAME -H pr-404 -t "\$(gh auth token)"

  $SCRIPT_NAME -H pr-404 -p stable/cgc-challenges/ -t "\$(gh auth token)"

Options:
  -d, --snapshot-directory

      Specify the directory to cache the decompilation snapshots.

  -h, --help

      Show this help message and exit

  -p <path>, --path <path>

      The file path of the snapshot to compare.

  -v, --verbose

      Enable more verbose output.

GitHub Options:

  -b <ref>, --base-ref <ref>

      The name of the base repository ref to compare snapshots from. This
      defaults to HEAD.

  -H <ref>, --head-ref <ref>

      The name of the head repository ref to compare snapshots to.

  -R <repo>, --repo <repo>

      The GitHub repository to enumerate using the OWNER/REPO format.
      This defaults to project-purcellville/snapshots-0000.

  -t <token>, --token <token>

      A GitHub token with access permissions. This can also be specified via the
      GITHUB_TOKEN environment variable.
ANGR
  exit 1
}

declare -a FILEPATH
REF_BASE="HEAD"
REPO="project-purcellville/snapshots-0000"
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
SNAPSHOT_DIR=""
VERBOSE=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -b|--base-ref)
        REF_BASE="${2}"
        shift 2
        ;;
      -d|--snapshot-dir)
        SNAPSHOT_DIR="${2}"
        shift 2
        ;;
      -h|--help)
        help
        ;;
      -H|--head-ref)
        REF_HEAD="$2"
        shift 2
        ;;
      -p|--path)
        FILEPATH+=("$2")
        shift 2
        ;;
      -R|--repo)
        REPO="$2"
        shift 2
        ;;
      -t|--token)
        GITHUB_TOKEN="$2"
        shift 2
        ;;
      -v|--verbose)
        VERBOSE=true
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

if [[ -z "${REF_HEAD}" ]]; then
  echo "ERROR: head <ref> not provided"
  echo
  help
fi

if [[ -z "${SNAPSHOT_DIR}" ]]; then
  trap 'rm -rf "$TEMP_DIR"' EXIT
  SNAPSHOT_DIR=$(mktemp -d)
else
  mkdir -p "${SNAPSHOT_DIR}"
fi

# Retrieve a list of all of the available snapshot file paths.
if ! [[ -f "${SNAPSHOT_DIR}/index_${REF_HEAD}.txt" ]]; then
  printf "Indexing remote: %s\n" "${REF_HEAD}" >&2
  "${SCRIPT_DIR}/gh_ls.sh" \
    -R "${REPO}" \
    --branch "${REF_HEAD}" \
    --path snapshots/ \
    --token "${GITHUB_TOKEN}" \
    >> "${SNAPSHOT_DIR}/index_${REF_HEAD}.txt"
fi

# If FILEPATHs were provided, call `gh_ls.sh` and retrieve all available
# valid file paths in case they were file patterns.
if ! [[ "${#FILEPATH[@]}" -eq 0 ]]; then
  declare -a FILEPATH_NEW
  for index in "${!FILEPATH[@]}"; do
    printf "\rHydrating remote path: %s" "${FILEPATH[$index]}" >&2
    if [[ "${FILEPATH[$index]}" != snapshots/* ]]; then
      FILEPATH[index]="snapshots/${FILEPATH[$index]}"
    fi
    declare -a FILEPATH_TMP
    mapfile -t FILEPATH_TMP < <(
      "${SCRIPT_DIR}/gh_ls.sh" \
        -R "${REPO}" \
        --branch "${REF_HEAD}" \
        --path "${FILEPATH[$index]}" \
        --token "${GITHUB_TOKEN}"
    )
    FILEPATH_NEW=( "${FILEPATH_NEW[@]}" "${FILEPATH_TMP[@]}" )
  done
  FILEPATH=("${FILEPATH_NEW[@]}")
  printf "\33[2K\rHydrated %s snapshot paths, done.\n" "${#FILEPATH_NEW[@]}" >&2
fi

# Try and find a PR merging from the `REF_HEAD` to the `REF_BASE` and get a list
# of only the files with changes.
if [[ "${#FILEPATH[@]}" -eq 0 ]]; then
  mapfile -t FILEPATH < <(
    gh pr list \
      -R "${REPO}" \
      --json headRefName \
      --json files \
      --jq ".[] | select(.headRefName == \"$REF_HEAD\")
                | .files[].path"
  )
  printf "Selected changed files from PR: %s\n" "${#FILEPATH[@]}" >&2
fi

# If there are still no file paths, get the list of paths from the head ref.
if [[ "${#FILEPATH[@]}" -eq 0 ]]; then
  mapfile -t FILEPATH < <(sort "${SNAPSHOT_DIR}/index_${REF_HEAD}.txt")
fi

# Download each snapshot.
# If the FILEPATH is missing a leading `snapshots/`, add it.
# If it is missing a trailing `.json.txt`, add it.
N="${N:-$(($(getconf _NPROCESSORS_ONLN) * 2))}"

for index in "${!FILEPATH[@]}"; do
  printf "\33[2K\rDownloading snapshots (%s/%s)" "$((index + 1))" "${#FILEPATH[@]}" >&2

  if [[ "${FILEPATH[$index]}" != snapshots/* ]]; then
    FILEPATH[index]="snapshots/${FILEPATH[$index]}"
  fi
  if [[ "${FILEPATH[$index]}" != *.json.txt ]]; then
    FILEPATH[index]="${FILEPATH[$index]}.json.txt"
  fi

  # Concurrency control. Let up to ${N} jobs run in the background.
  mapfile -t pids < <(jobs -pr)
  [[ ${#pids[@]} -ge ${N} ]] && wait -n
  unset pids

  DIRPATH="${SNAPSHOT_DIR}/${REF_BASE}/$(dirname "${FILEPATH[$index]}")"
  FILENAME="$(basename "${FILEPATH[$index]}")"
  mkdir -p "${DIRPATH}"
  SNAPSHOT_BASE_URL="https://raw.githubusercontent.com/${REPO}/${REF_BASE}/${FILEPATH[$index]}"
  if ! [[ -f "${DIRPATH}/${FILENAME}" ]]; then
    curl \
      --location \
      --header "Authorization: token $GITHUB_TOKEN" \
      --output "${DIRPATH}/${FILENAME}" \
      --silent \
      "${SNAPSHOT_BASE_URL}" &
  fi

  DIRPATH="${SNAPSHOT_DIR}/${REF_HEAD}/$(dirname "${FILEPATH[$index]}")"
  FILENAME="$(basename "${FILEPATH[$index]}")"
  mkdir -p "${DIRPATH}"
  SNAPSHOT_URL="https://raw.githubusercontent.com/${REPO}/${REF_HEAD}/${FILEPATH[$index]}"
  if ! [[ -f "${DIRPATH}/${FILENAME}" ]]; then
    curl \
      --location \
      --header "Authorization: token $GITHUB_TOKEN" \
      --output "${DIRPATH}/${FILENAME}" \
      --silent \
      "${SNAPSHOT_URL}" &
  fi
done

wait
echo ", done." >&2

# XXX: This was indulgent. Revisit performance here.
{
  for index in "${!FILEPATH[@]}"; do
    SNAPSHOT1="${SNAPSHOT_DIR}/${REF_BASE}/${FILEPATH[$index]}"
    SNAPSHOT2="${SNAPSHOT_DIR}/${REF_HEAD}/${FILEPATH[$index]}"

    if [[ -n "${VERBOSE}" ]]; then
      "${SCRIPT_DIR}/classify_diff.sh" -v "${SNAPSHOT1}" "${SNAPSHOT2}"
    else
      "${SCRIPT_DIR}/classify_diff.sh" "${SNAPSHOT1}" "${SNAPSHOT2}"
    fi
  done
} | \
jq 'select(.identical == false)' | \
jq -s 'reduce(.[].changes |
              to_entries[] |
              select(.value != 0)) as {"key": $key, "value": $value}
       ({}; .["changes"][$key]["hunks"] += $value |
            .["changes"][$key]["files"] += 1)' | \
jq -r '.changes |
       to_entries |
       ["-----------,-----,-----"] +
       map("\(.key | gsub("_"; " ") | ascii_upcase),\(.value.hunks),\(.value.files)") |
       .[]' | \
column -t -N "Change Type,Hunks,Files" -o " | " -s ","
