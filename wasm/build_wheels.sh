#!/usr/bin/env bash
set -euo pipefail

angr_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${ANGR_WASM_WORKSPACE:-$(dirname "$angr_dir")}"
pyodide_version="${PYODIDE_VERSION:-314.0.2}"
xbuildenv_path="${PYODIDE_XBUILDENV_PATH:-$workspace/.pyodide-xbuildenv}"
out_dir="$angr_dir/wasm/dist"
sample_dir="$angr_dir/wasm/samples"
pyodide=(uvx --python 3.14 --from 'pyodide-build[resolve]' pyodide)
source_repos=(archinfo claripy cle pypcode pyvex)

missing_repos=()
for repo in "${source_repos[@]}"; do
    if [[ ! -d "$workspace/$repo" ]]; then
        missing_repos+=("$repo")
    fi
done
if (( ${#missing_repos[@]} )); then
    uv run --project "$angr_dir" --no-sync python "$angr_dir/wasm/materialize_uv_sources.py" \
        "$workspace" "${missing_repos[@]}"
fi

for repo in "${source_repos[@]}" z3; do
    if [[ ! -d "$workspace/$repo" ]]; then
        echo "Missing sibling repository: $workspace/$repo" >&2
        exit 1
    fi
done

mkdir -p "$out_dir"
rm -f "$out_dir"/*.whl

sample_source="${ANGR_WASM_SAMPLE_BINARY:-$workspace/binaries/tests/x86_64/fauxware}"
mkdir -p "$sample_dir"
rm -f "$sample_dir/fauxware"
if [[ -f "$sample_source" ]]; then
    cp "$sample_source" "$sample_dir/fauxware"
else
    echo "Fauxware sample not found at $sample_source; the upload demo will still work" >&2
fi

export PYODIDE_XBUILDENV_PATH="$xbuildenv_path"
"${pyodide[@]}" xbuildenv install "$pyodide_version" --path "$xbuildenv_path"
emscripten_version="$("${pyodide[@]}" config get emscripten_version)"
"${pyodide[@]}" xbuildenv install-emscripten --version "$emscripten_version" --path "$xbuildenv_path"

emsdk_env="$xbuildenv_path/$pyodide_version/emsdk/emsdk_env.sh"
if [[ ! -f "$emsdk_env" ]]; then
    echo "Emscripten was not installed at $emsdk_env" >&2
    exit 1
fi
export EMSDK_QUIET=1
source "$emsdk_env"

git -C "$workspace/pyvex" submodule update --init --recursive
"${pyodide[@]}" build "$workspace/pyvex" --xbuildenv-path "$xbuildenv_path" --outdir "$out_dir"
"${pyodide[@]}" build "$workspace/pypcode" --xbuildenv-path "$xbuildenv_path" --outdir "$out_dir"
real_make="$(command -v make)"
PATH="$angr_dir/wasm/z3-build-tools:$PATH" ANGR_WASM_REAL_MAKE="$real_make" \
    "${pyodide[@]}" build "$workspace/z3/src/api/python" --xbuildenv-path "$xbuildenv_path" --outdir "$out_dir"
"${pyodide[@]}" build 'capstone==5.0.6' --xbuildenv-path "$xbuildenv_path" --outdir "$out_dir"
"${pyodide[@]}" build 'pydemumble==0.0.1' --xbuildenv-path "$xbuildenv_path" --outdir "$out_dir"

uv build --wheel --out-dir "$out_dir" "$workspace/archinfo"
uv build --wheel --out-dir "$out_dir" "$workspace/claripy"
uv build --wheel --out-dir "$out_dir" "$workspace/cle"
python3 -m pip wheel --no-deps --wheel-dir "$out_dir" 'mulpyplexer==0.09' 'arpy==1.1.1'

(
    cd "$angr_dir"
    rustup target add wasm32-unknown-emscripten
)

# Do not package stale modules or extensions from a prior native build.
if [[ -d "$angr_dir/build" ]]; then
    find "$angr_dir/build" -depth -delete
fi
find "$angr_dir/angr" -maxdepth 1 -type f \( -name 'rustylib*.so' -o -name 'unicornlib.so' \) -delete

uvx --python 3.14 --from 'pyodide-build[resolve]' --with 'setuptools>=77' --with setuptools-rust --with wheel \
    --with 'grpcio-tools~=1.80.0' --with 'protobuf>=6.31.1,<7' \
    pyodide build "$angr_dir" --xbuildenv-path "$xbuildenv_path" --no-isolation --skip-dependency-check \
    --outdir "$out_dir"

python3 "$angr_dir/wasm/make_manifest.py"
