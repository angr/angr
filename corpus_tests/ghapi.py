#!/usr/bin/env python3

import requests
import argparse
import subprocess
import hashlib
import sys
import base64
import logging
from typing import Optional

# Default values
DEFAULT_OWNER = "project-purcellville"
DEFAULT_REPO = "snapshots-0000"
DEFAULT_BRANCH = "main"
DEFAULT_USER = "github-actions[bot]"
DEFAULT_EMAIL = "github-actions[bot]@users.noreply.github.com"
DEFAULT_COMMIT_MESSAGE = "update file contents"

# Setup logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

class GitHubRepo:
    def __init__(self, owner: str, repo: str, auth_token: Optional[str] = None, branch: str = DEFAULT_BRANCH,
                 user: str = DEFAULT_USER, email: str = DEFAULT_EMAIL):
        self.owner = owner
        self.repo = repo
        self.auth_token = auth_token if auth_token else self.get_default_token()
        self.branch = branch
        self.user = user
        self.email = email

    def get_default_token(self) -> str:
        try:
            result = subprocess.run(['gh', 'auth', 'token'], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to retrieve GitHub auth token using `gh auth token`: {e}")
            raise RuntimeError("Failed to retrieve GitHub auth token using `gh auth token`")

    def get_branch_sha(self) -> Optional[str]:
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/git/refs/heads/{self.branch}"
        logger.debug(f"Hitting URL: {url}")
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data['object']['sha']
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve branch data: {e}")
            return None

    def create_branch(self, new_branch: str, allow_existing_branch: bool) -> bool:
        if self.check_branch_exists(new_branch):
            if allow_existing_branch:
                logger.info(f"Branch '{new_branch}' already exists.")
                return True
            else:
                logger.error(f"Branch '{new_branch}' already exists.")
                return False

        sha = self.get_branch_sha()
        if not sha:
            logger.error(f"Failed to get SHA for branch '{self.branch}'")
            return False

        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/git/refs"
        logger.debug(f"Hitting URL: {url}")
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        data = {
            "ref": f"refs/heads/{new_branch}",
            "sha": sha
        }

        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            logger.info(f"Branch '{new_branch}' created successfully from '{self.branch}'")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to create branch '{new_branch}': {e}")
            return False

    def get_file_sha(self, file_path: str) -> Optional[str]:
        branch_sha = self.get_branch_sha()
        if not branch_sha:
            logger.error(f"Failed to get SHA for branch '{self.branch}'")
            return None

        commit_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/git/commits/{branch_sha}"
        logger.debug(f"Hitting URL: {commit_url}")
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        try:
            commit_response = requests.get(commit_url, headers=headers)
            commit_response.raise_for_status()
            commit_data = commit_response.json()
            tree_sha = commit_data['tree']['sha']
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve commit data: {e}")
            return None

        file_parts = file_path.split('/')
        for part in file_parts:
            tree_url = f"https://api.github.com/repos/{self.owner}/{self.repo}/git/trees/{tree_sha}"
            logger.debug(f"Hitting URL: {tree_url}")
            try:
                tree_response = requests.get(tree_url, headers=headers)
                tree_response.raise_for_status()
                tree_data = tree_response.json()
            except requests.RequestException as e:
                logger.error(f"Failed to retrieve tree data: {e}")
                return None

            found = False
            for item in tree_data['tree']:
                if item['path'] == part:
                    if item['type'] == 'tree':
                        tree_sha = item['sha']
                    elif item['type'] == 'blob' and part == file_parts[-1]:
                        return item['sha']
                    found = True
                    break

            if not found:
                logger.error(f"File '{file_path}' not found in the repository")
                return None

        return None

    def calculate_blob_sha(self, file_path: str) -> str:
        with open(file_path, 'rb') as f:
            content = f.read()
        size = len(content)
        header = f'blob {size}\0'.encode('utf-8')
        store = header + content
        sha1 = hashlib.sha1(store).hexdigest()
        return sha1

    def push_file(self, local_file_path: str, repo_file_path: str, commit_message: str) -> bool:
        local_sha = self.calculate_blob_sha(local_file_path)
        remote_sha = self.get_file_sha(repo_file_path)

        if local_sha == remote_sha:
            logger.info(f"No changes detected in '{local_file_path}'.")
            return True

        with open(local_file_path, 'rb') as f:
            content = f.read()

        encoded_content = base64.b64encode(content).decode('utf-8')

        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/contents/{repo_file_path}"
        logger.debug(f"Hitting URL: {url}")
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        data = {
            "message": f"{commit_message} [{repo_file_path}]",
            "committer": {
                "name": self.user,
                "email": self.email
            },
            "content": encoded_content,
            "branch": self.branch
        }

        if remote_sha:
            data["sha"] = remote_sha

        try:
            response = requests.put(url, headers=headers, json=data)
            response.raise_for_status()
            logger.info(f"File '{local_file_path}' pushed successfully.")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to push file '{local_file_path}': {e}")
            return False

    def create_pr(self, branch_to_merge: str, title: str) -> bool:
        branch_exists = self.check_branch_exists(branch_to_merge)
        if not branch_exists:
            logger.error(f"Branch '{branch_to_merge}' does not exist.")
            return False

        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/pulls"
        logger.debug(f"Hitting URL: {url}")
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        data = {
            "title": title,
            "head": f"{self.owner}:{branch_to_merge}",
            "base": self.branch
        }

        try:
            response = requests.post(url, headers=headers, json=data)
            response.raise_for_status()
            pr_url = response.json().get("html_url")
            logger.info(f"Pull request created successfully for branch '{branch_to_merge}' into '{self.branch}'.")
            logger.info(f"Pull request URL: {pr_url}")
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to create pull request: {e}")
            return False

    def check_branch_exists(self, branch_name: str) -> bool:
        url = f"https://api.github.com/repos/{self.owner}/{self.repo}/git/refs/heads/{branch_name}"
        logger.debug(f"Hitting URL: {url}")
        headers = {
            "Authorization": f"token {self.auth_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        try:
            response = requests.get(url, headers=headers)
            return response.status_code == 200
        except requests.RequestException as e:
            logger.error(f"Failed to check if branch exists: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="GitHubRepo Utility")
    parser.add_argument("--owner", "-O", type=str, default=DEFAULT_OWNER, help=f"Repository owner [\"{DEFAULT_OWNER}\"]")
    parser.add_argument("--repo", "-R", type=str, default=DEFAULT_REPO, help=f"Repository name [\"{DEFAULT_REPO}\"]")
    parser.add_argument("--auth-token", "-A", type=str, default=None, help="GitHub authentication token [gh auth token]")
    parser.add_argument("--branch", "-b", type=str, default=DEFAULT_BRANCH, help=f"Source branch name [\"{DEFAULT_BRANCH}\"]")
    parser.add_argument("--user", "-u", type=str, default=DEFAULT_USER, help=f"Committer username [\"{DEFAULT_USER}\"]")
    parser.add_argument("--email", "-e", type=str, default=DEFAULT_EMAIL, help=f"Committer email [\"{DEFAULT_EMAIL}\"]")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    subparsers = parser.add_subparsers(dest="command")

    get_branch_sha_parser = subparsers.add_parser("get_branch_sha", help="Get the SHA of the specified branch")

    create_branch_parser = subparsers.add_parser("create_branch", help="Create a new branch from the specified branch")
    create_branch_parser.add_argument("new_branch", type=str, help="New branch name")
    create_branch_parser.add_argument("--allow-existing-branch", action='store_true', help="Allow the branch to exist without error")

    get_file_sha_parser = subparsers.add_parser("get_file_sha", help="Get the SHA of a file at the specified path")
    get_file_sha_parser.add_argument("file_path", type=str, help="Path of the file in the repository")

    push_file_parser = subparsers.add_parser("push_file", help="Push a file to the repository if its SHA differs")
    push_file_parser.add_argument("local_file_path", type=str, help="Path to the local file")
    push_file_parser.add_argument("repo_file_path", type=str, help="Path to the file in the repository")
    push_file_parser.add_argument("commit_message", type=str, nargs='?', default=DEFAULT_COMMIT_MESSAGE, help=f"Commit message [\"{DEFAULT_COMMIT_MESSAGE}\"]")

    create_pr_parser = subparsers.add_parser("create_pr", help="Create a pull request")
    create_pr_parser.add_argument("branch_to_merge", type=str, help="Branch to be merged")
    create_pr_parser.add_argument("title", type=str, help="Title of the pull request")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    github_repo = GitHubRepo(owner=args.owner, repo=args.repo, auth_token=args.auth_token, branch=args.branch,
                             user=args.user, email=args.email)

    if args.command == "get_branch_sha":
        sha = github_repo.get_branch_sha()
        if sha:
            logger.info(f"The SHA of the branch '{args.branch}' is: {sha}")
            sys.exit(0)
        else:
            logger.error("Failed to retrieve the branch SHA.")
            sys.exit(1)
    elif args.command == "create_branch":
        success = github_repo.create_branch(args.new_branch, args.allow_existing_branch)
        if success:
            sys.exit(0)
        else:
            logger.error("Failed to create the new branch.")
            sys.exit(1)
    elif args.command == "get_file_sha":
        sha = github_repo.get_file_sha(args.file_path)
        if sha:
            logger.info(f"The SHA of the file '{args.file_path}' is: {sha}")
            sys.exit(0)
        else:
            logger.error("Failed to retrieve the file SHA.")
            sys.exit(1)
    elif args.command == "push_file":
        success = github_repo.push_file(args.local_file_path, args.repo_file_path, args.commit_message)
        if success:
            sys.exit(0)
        else:
            logger.error("Failed to push the file.")
            sys.exit(1)
    elif args.command == "create_pr":
        success = github_repo.create_pr(args.branch_to_merge, args.title)
        if success:
            sys.exit(0)
        else:
            logger.error("Failed to create the pull request.")
            sys.exit(1)

if __name__ == "__main__":
    main()
