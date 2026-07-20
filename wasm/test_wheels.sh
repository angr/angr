#!/usr/bin/env bash
set -euo pipefail

angr_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${ANGR_WASM_WORKSPACE:-$(dirname "$angr_dir")}"
xbuildenv_path="${PYODIDE_XBUILDENV_PATH:-$workspace/.pyodide-xbuildenv}"
venv_dir="${ANGR_WASM_VENV:-$workspace/.angr-wasm-venv}"
pyodide=(uvx --python 3.14 --from 'pyodide-build[resolve]' pyodide)

if [[ -z "${ANGR_WASM_TEST_BINARY:-}" ]]; then
    echo "Set ANGR_WASM_TEST_BINARY to the x86-64 fauxware test binary" >&2
    exit 1
fi

export PYODIDE_XBUILDENV_PATH="$xbuildenv_path"
"${pyodide[@]}" venv --clear "$venv_dir"
source "$venv_dir/bin/activate"
cd "$venv_dir"
python -m pip install --force-reinstall "$angr_dir"/wasm/dist/*.whl
python "$angr_dir/wasm/smoke_test.py"
