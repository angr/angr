#!/bin/bash

script_name=$(basename "$0")

verbose=0
create_branch=0
auth_token=$(gh auth token)
gh_owner=project-purcellville
gh_repo=snapshots-0000
gh_branch=dr-test

log_error() {
    echo -e "${script_name}: $@" 1>&2
}

log_debug() {
    if [[ $verbose == 1 ]]; then
        echo -e "$@" 1>&2
    fi
}

usage() {
    echo ""
    echo "Usage: ${script_name} [OPTIONS] local-file-path file-path-in-repo"
    echo ""
    echo "Creates or updates a file in a remote repository using the GitHub"
    echo "REST API. This avoids the need to clone the repository first."
    echo ""
    echo "OPTIONS"
    echo ""
    echo "    -h          Show usage information."
    echo "    -v          Show debug/verbose messages."
    echo "    -a AUTH     Authentication token. [from 'gh auth token']"
    echo "    -o OWNER    GitHub owner (organization). ['${gh_owner}']"
    echo "    -r REPO     GitHub repository name. ['${gh_repo}']"
    echo "    -b BRANCH   Branch within repository. ['${gh_branch}']"
    echo "    -B SOURCE   Create branch from 'refs/heads/SOURCE' before pushing."
    echo ""
}

while getopts "hva:o:r:b:B:" opt; do
    case $opt in
        h)
            usage
            exit 0
            ;;
        v)
            verbose=1
            ;;
        a)
            auth_token="$OPTARG"
            ;;
        o)
            gh_owner="$OPTARG"
            ;;
        r)
            gh_repo="$OPTARG"
            ;;
        b)
            gh_branch="$OPTARG"
            ;;
        B)
            create_branch=1
            gh_source_branch="$OPTARG"
            ;;
    esac
done

shift $[OPTIND - 1]

if [[ $# -ne 2 ]]; then
    log_error "not all arguments provided; use '${script_name} -h' for usage"
    exit 1
fi

local_file_path="$1"
file_path_in_repo="$2"

if [[ ! -e "$local_file_path" ]]; then
    log_error "$0: file '$local_file_path' does not exist" 1>&2
    exit 2
fi

if [[ $create_branch == 1 ]]; then
    response_json=$(curl -s\
        -X GET \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${auth_token}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${gh_owner}/${gh_repo}/git/ref/heads/${gh_source_branch}")
    log_debug "Source branch '${gh_source_branch}' response:${response_json}"
    source_branch_sha=$(echo $response_json | jq .object.sha | tr -d '"')
    log_debug "Source branch sha: ${source_branch_sha}"

    if [[ $source_branch_sha == "null" ]]; then
        log_error "Could not find source branch '$gh_source_branch' in repo."
        exit 2
    fi

    response_json=$(curl -s\
        -X POST \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer ${auth_token}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "https://api.github.com/repos/${gh_owner}/${gh_repo}/git/refs" \
        -d "{\"ref\":\"refs/heads/${gh_branch}\",\"sha\":\"${source_branch_sha}\"}")
    log_debug "Create branch '${gh_branch}' response:${response_json}"

    new_ref=$(echo "$response_json" | jq .ref | tr -d '"')
    if [[ "$new_ref" != "refs/heads/${gh_branch}" ]]; then
        log_error "Could not create new branch '${gh_branch}'."
        exit 2
    fi

    echo "Created branch '${gh_branch}' based at '${gh_source_branch}'."
fi

file_content="$(cat $local_file_path | base64 | tr -d '\n')"

# Calculate local file blob sha to compare with current file in repo.
local_file_blob_sha="$((stat --printf='blob %s\0' $local_file_path; cat $local_file_path) | sha1sum | grep -o '[0-9a-f]*')"

# This works, but it includes "content": "<base64-file-contents>", which is
# inefficient for medium-to-large file sizes.

# remote_file_json=$(curl -L \
#   -X GET \
#   -H "Accept: application/vnd.github+json" \
#   -H "Authorization: Bearer ${auth_token}" \
#   -H "X-GitHub-Api-Version: 2022-11-28" \
#   "https://api.github.com/repos/${gh_owner}/${gh_repo}/contents/${file_path_in_repo}?ref=${gh_branch}")

# This method gets the file info of all items in a directory, without the
# need to download the file's contents. The directory entries could be more
# than the file contents, though!
remote_dir=$(dirname "$file_path_in_repo")
remote_file=$(basename "$file_path_in_repo")
remote_url="https://api.github.com/repos/${gh_owner}/${gh_repo}/git/trees/${gh_branch}:${remote_dir}"

log_debug "local_file_blob_sha=$local_file_blob_sha"
log_debug "remote_dir='$remote_dir'"
log_debug "remote_file='$remote_file'"
log_debug "remote_url='$remote_url'"

remote_file_json=$(curl -sL \
  -X GET \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${auth_token}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "${remote_url}")

# log_debug "remote_file_json=|${remote_file_json}|"

blob_sha_field=""

if [[ "$(echo $remote_file_json | jq '.status' 2>/dev/null)" != "null" ]]; then
    log_debug "dir '${gh_branch}:${remote_dir}' not found in ${gh_owner}/{gh_repo}; will create it."
else
    sha=$(echo "$remote_file_json" | jq ".tree | .[] | select(.path==\"${remote_file}\") | .sha" 2>/dev/null)
    if [[ -z "$sha" ]]; then
        log_debug "file '${gh_branch}:${remote_dir}/${remote_file}' not found in ${gh_owner}/{gh_repo}; will create it."
    else
        remote_file_blob_sha=$(echo $sha | grep -o '[0-9a-f]*')
        log_debug "blob sha for existing '${gh_branch}:${remote_dir}/${remote_file}': ${remote_file_blob_sha}"

        if [[ "${remote_file_blob_sha}" == "${local_file_blob_sha}" ]]; then
            echo "local file '${local_file_path}' unchanged from '${gh_branch}:${remote_dir}/${remote_file}'; not updating."
            exit 0
        else
            log_debug "local file '${local_file_path}' differs from '${gh_branch}:${remote_dir}/${remote_file}'; will update."
            blob_sha_field="\"sha\":\"${remote_file_blob_sha}\","
        fi
    fi
fi

data_json="{\"message\":\"adding ${file_path_in_repo}\",\
\"committer\":{\"name\":\"User Name\",\"email\":\"username@example.com\"},\
\"branch\":\"${gh_branch}\",\
${blob_sha_field}\
\"content\":\"${file_content}\"}"

if [[ $verbose == 1 ]]; then
    log_debug "writing data_json to data_json.out"
    echo "data_json=$data_json" > data_json.out
fi

result_json=$(curl -sL \
  -X PUT \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer ${auth_token}" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/${gh_owner}/${gh_repo}/contents/${file_path_in_repo}" \
  -d "$data_json")

log_debug "result_json=${result_json}"

result_path="$(echo $result_json | jq '.content.path' | tr -d '"')"

if [[ "${result_path}" != "${file_path_in_repo}" ]]; then
    log_error "failed to update '${gh_branch}:${path_in_repo}'; '${result_path}' not equal to '${file_path_in_repo}'"
    log_error "returned JSON:\n${result_json}"
    exit 1
fi

echo "'${gh_branch}:${path_in_repo}' successfully written/updated."
exit 0
