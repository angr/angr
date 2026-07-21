from __future__ import annotations

import json
from pathlib import Path

PYODIDE_VERSION = "314.0.2"
REQUIRED_DISTRIBUTIONS = (
    "z3_solver",
    "capstone",
    "pydemumble",
    "pypcode",
    "pyvex",
    "archinfo",
    "claripy",
    "cle",
    "mulpyplexer",
    "arpy",
    "angr",
)


def main() -> None:
    wasm_dir = Path(__file__).resolve().parent
    dist_dir = wasm_dir / "dist"
    wheels = list(dist_dir.glob("*.whl"))
    packages: list[str] = []

    for distribution in REQUIRED_DISTRIBUTIONS:
        matches = [wheel for wheel in wheels if wheel.name.lower().startswith(f"{distribution}-")]
        if len(matches) != 1:
            raise SystemExit(f"Expected one {distribution} wheel in {dist_dir}, found {len(matches)}")
        packages.append(f"./dist/{matches[0].name}")

    manifest = {
        "pyodideIndexURL": f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/",
        "packages": packages,
    }
    (wasm_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
