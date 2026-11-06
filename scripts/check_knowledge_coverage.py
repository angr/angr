#!/usr/bin/env python3
"""Check that new .py files under angr/ are covered by the docs/agents/ knowledge base.

Uses OpenAI gpt-5.2 to semantically judge whether each new file is mentioned
or covered in the existing knowledge base docs.

Exit code 0 = all covered (or no new files). Exit code 1 = gaps found.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

KNOWLEDGE_DIR = Path("docs/agents")
MAX_LINES_PER_FILE = 200


def get_new_py_files() -> list[str]:
    """Find .py files added in this PR or push."""
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    if event == "pull_request":
        base = "origin/master"
        cmd = ["git", "diff", "--name-only", "--diff-filter=A", f"{base}...HEAD"]
    else:
        # push to master — compare against parent
        cmd = ["git", "diff", "--name-only", "--diff-filter=A", "HEAD~1...HEAD"]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    files = result.stdout.strip().splitlines()
    return [f for f in files if f.startswith("angr/") and f.endswith(".py")]


def load_knowledge_base() -> str:
    """Read all docs/agents/*.md into a single string."""
    parts = []
    for md in sorted(KNOWLEDGE_DIR.glob("*.md")):
        parts.append(f"--- {md.name} ---\n{md.read_text()}")
    return "\n\n".join(parts)


def read_file_head(path: str) -> str:
    """Read up to MAX_LINES_PER_FILE lines of a file."""
    try:
        lines = Path(path).read_text().splitlines()[:MAX_LINES_PER_FILE]
        return "\n".join(lines)
    except Exception as e:
        return f"<error reading file: {e}>"


def check_coverage(new_files: list[str], knowledge: str) -> list[dict]:
    """Ask gpt-5.2 whether each new file is covered by the knowledge base."""
    file_snippets = []
    for f in new_files:
        content = read_file_head(f)
        file_snippets.append({"path": f, "content": content})

    from openai import OpenAI

    client = OpenAI()

    response = client.responses.create(
        model="gpt-5.2",
        instructions=(
            "You are a documentation coverage checker for the angr project. "
            "You will receive the full contents of the docs/agents/ knowledge base, "
            "plus a list of newly added Python files with their content. "
            "For each file, determine whether the knowledge base already covers it — "
            "meaning the file's purpose, module, or functionality is mentioned or "
            "described in the docs. A file counts as covered if its parent module, "
            "directory, or the functionality it implements is documented, even if the "
            "exact filename isn't listed. "
            "Return ONLY valid JSON with this schema: "
            '{"files": [{"path": "<path>", "covered": true/false, "reason": "<brief explanation>"}]}'
        ),
        input=[
            {
                "role": "user",
                "content": (
                    "## Knowledge Base\n\n"
                    f"{knowledge}\n\n"
                    "## New Files to Check\n\n"
                    f"{json.dumps(file_snippets, indent=2)}"
                ),
            }
        ],
        text={"format": {"type": "json_object"}},
    )

    return json.loads(response.output_text)["files"]


def main():
    new_files = get_new_py_files()

    if not new_files:
        print("No new .py files under angr/ — nothing to check.")
        sys.exit(0)

    print(f"Found {len(new_files)} new .py file(s) to check:")
    for f in new_files:
        print(f"  {f}")
    print()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY not set. Cannot check coverage.")
        sys.exit(1)

    knowledge = load_knowledge_base()
    results = check_coverage(new_files, knowledge)

    # Print results table
    uncovered = []
    print(f"{'Path':<60} {'Covered':<10} Reason")
    print("-" * 120)
    for entry in results:
        path = entry["path"]
        covered = entry["covered"]
        reason = entry["reason"]
        status = "YES" if covered else "NO"
        print(f"{path:<60} {status:<10} {reason}")
        if not covered:
            uncovered.append(entry)

    print()
    if uncovered:
        print(f"FAIL: {len(uncovered)} new file(s) not covered by docs/agents/:")
        for entry in uncovered:
            print(f"  - {entry['path']}: {entry['reason']}")
        sys.exit(1)
    else:
        print("PASS: All new files are covered by the knowledge base.")
        sys.exit(0)


if __name__ == "__main__":
    main()
