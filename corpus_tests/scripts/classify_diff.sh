#!/usr/bin/env bash

set -o pipefail

help() {
  SCRIPT_NAME="$(basename "$0")"
  cat <<ANGR
Usage: $SCRIPT_NAME <snapshot1> <snapshot2> [OPTIONS]

  Compares 1-to-1 decompilation snapshots and summarizes the change output.

Examples:
  $SCRIPT_NAME snapshots/{HEAD,pr-404}/Palindrome.exe.json.txt

Options:
  -h, --help

      Show this help message and exit

  -v, --verbose

      Enable more verbose output.
ANGR
  exit 1
}

declare -a REST
VERBOSE=""

parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
      -h|--help)
        help
        ;;
      -v|--verbose)
        VERBOSE=true
        shift 1
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

# Handle the case where the first file does not exist.
# Happens when we want to add a new snapshot to the repository.
if [[ ! -f "${REST[0]}" && -f "${REST[1]}" ]]; then
  cat <<ANGR | jq -cMr
{
  "identical": false,
  "new": true,
  "changes": {}
}
ANGR
  exit 0
fi

trap 'rm -rf "$TEMP_DIR"' EXIT
TEMP_DIR=$(mktemp -d)
HUNK_DIR="${TEMP_DIR}/hunks"
mkdir -p "${HUNK_DIR}"

diff -u \
  <(echo -e "$(cat "${REST[0]}")") \
  <(echo -e "$(cat "${REST[1]}")") > "${TEMP_DIR}/diff.patch"
[[ -n "${VERBOSE}" ]] && cat "${TEMP_DIR}/diff.patch" >&2

# Handle the case that the two files are the same.
if ! [[ -s "${TEMP_DIR}/diff.patch" ]]; then
  cat <<ANGR | jq -cMr
{
  "identical": true,
  "new": false,
  "changes": {}
}
ANGR

  exit 0
fi

# Extract each hunk to a separate file for analysis.
temp_file=$(mktemp)
hunk_count=0
in_hunk=0

while IFS= read -r line; do
  # Check for hunk header.
  if [[ $line =~ @@[[:space:]]+([-+]?[0-9]+,[-+]?[0-9]+)[[:space:]]+([-+]?[0-9]+,[-+]?[0-9]+) ]]; then
    # If we were processing a previous hunk, save it.
    if [[ $in_hunk -eq 1 ]]; then
      mv "$temp_file" "${HUNK_DIR}/hunk_${hunk_count}.diff"
      temp_file=$(mktemp)
    fi

    # Increment hunk counter and start new hunk.
    ((hunk_count++))
    in_hunk=1

    echo "$line" >> "$temp_file"
  elif [[ $in_hunk -eq 1 ]]; then
    # Add line to current hunk
    echo "$line" >> "$temp_file"
  fi
done < "${TEMP_DIR}/diff.patch"

# Save the last hunk if there is one.
if [[ $in_hunk -eq 1 ]]; then
  mv "$temp_file" "${HUNK_DIR}/hunk_${hunk_count}.diff"
else
  rm "$temp_file"
fi

# Classify each of the changes.

control_flow_logic=0
# - if (v2 < a2)
# + if (v2 >= a2)

function_signature=0
# -    v1 = cgc_allocate(a0, v6, v7);
# +    v1 = cgc_allocate(a0, v6, v7, v8);

pointer_deref=0
# - if (v2[a1] == a3)
# + if (*((a1 + v2)) == a3)

type_definition=0
# - unsigned long v0;  // [bp+0x0], Other Possible Types: char
# + char v0;  // [bp+0x0], Other Possible Types: unsigned long

undetermined=0

for i in $(seq 1 $hunk_count); do
  any_matched=0
  hunk_file="${HUNK_DIR}/hunk_${i}.diff"

  if grep -A1 "Possible Types:" "$hunk_file" | grep -qE "^[-+]"; then
    any_matched=1
    type_definition=$((type_definition + 1))
  fi

  if grep "if \|while \|for " "$hunk_file" | grep -qE "^[-+].*if|^[-+].*while|^[-+].*for"; then
    any_matched=1
    control_flow_logic=$((control_flow_logic + 1))
  fi

  if grep -A1 -B1 "\[\|->\\|\*(" "$hunk_file" | grep -qE "^[-+]"; then
    any_matched=1
    pointer_deref=$((pointer_deref + 1))
  fi

  if grep -qE '^-.*[a-zA-Z_][a-zA-Z0-9_]*\(.*\);|^\+.*[a-zA-Z_][a-zA-Z0-9_]*\(.*\);' "$hunk_file"; then
    any_matched=1
    function_signature=$((function_signature + 1))
  fi

  if [[ $any_matched -eq 0 ]]; then
    undetermined=$((undetermined + 1))
  fi
done

cat <<ANGR | jq -cMr
{
  "identical": false,
  "new": false,
  "changes": {
    "control_flow": ${control_flow_logic},
    "function_signature": ${function_signature},
    "pointer_deref": ${pointer_deref},
    "type_definition": ${type_definition},
    "undetermined": ${undetermined}
  }
}
ANGR
