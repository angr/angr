#!/usr/bin/env bash

set -eo pipefail

help() {
  SCRIPT_NAME="$(basename "$0")"
  cat <<ANGR
# Write a usage string that shows two mutually exclusive options like below but in
# standard format that utilities like git or ls might have.
Usage: $SCRIPT_NAME (<remote_path>) | (<local_snapshot1> <local_snapshot2>) [OPTIONS]

  Compares 1-to-1 decompilation snapshots for a particular file.

Examples:
  $SCRIPT_NAME -R project-purcellville/snapshots-0000 -b pr-404  -t "\$(gh auth token)"

  $SCRIPT_NAME -R project-purcellville/direct-file-store-0000 --branch pr-404 --path "stable/*/linux-build/"

  $SCRIPT_NAME -R project-purcellville/direct-file-store-0000 --branch pr-404 --path "*.dll"

Options:
  -h, --help

      Show this help message and exit

  -p <path>, --path <path>

      The file path of the snapshot to compare.

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
