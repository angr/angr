from __future__ import annotations

import argparse
import json
import subprocess
from importlib.metadata import distribution
from pathlib import Path
from tempfile import TemporaryDirectory


def source_revision(package: str) -> tuple[str, str]:
    direct_url = distribution(package).read_text("direct_url.json")
    if direct_url is None:
        raise RuntimeError(f"{package} was not installed from a VCS source; run uv sync first")

    metadata = json.loads(direct_url)
    vcs_info = metadata.get("vcs_info", {})
    url = metadata.get("url")
    commit = vcs_info.get("commit_id")
    if vcs_info.get("vcs") != "git" or not url or not commit:
        raise RuntimeError(f"{package} does not have Git source metadata")
    return url, commit


def materialize(workspace: Path, package: str) -> None:
    destination = workspace / package
    if destination.exists():
        return

    url, commit = source_revision(package)
    print(f"Materializing {package} at {commit}", flush=True)
    with TemporaryDirectory(prefix=f".{package}-", dir=workspace) as temporary:
        checkout = Path(temporary) / package
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", url, checkout], check=True)
        subprocess.run(["git", "-C", checkout, "checkout", "--detach", commit], check=True)
        subprocess.run(["git", "-C", checkout, "submodule", "update", "--init", "--recursive"], check=True)
        checkout.replace(destination)


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize the Git sources selected by uv sync")
    parser.add_argument("workspace", type=Path)
    parser.add_argument("packages", nargs="+")
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    for package in args.packages:
        materialize(workspace, package)


if __name__ == "__main__":
    main()
