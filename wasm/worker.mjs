let runtimePromise;
let uploadCounter = 0;

function convertResult(value) {
  if (value && typeof value.toJs === "function") {
    try {
      return value.toJs({ dict_converter: Object.fromEntries });
    } finally {
      value.destroy();
    }
  }
  return value;
}

async function initialize(manifestUrl = new URL("./manifest.json", import.meta.url).href) {
  manifestUrl = new URL(manifestUrl, import.meta.url).href;
  const manifestResponse = await fetch(manifestUrl);
  if (!manifestResponse.ok) {
    throw new Error(`Could not load angr wheel manifest: ${manifestResponse.status}`);
  }

  const manifest = await manifestResponse.json();
  const indexURL = manifest.pyodideIndexURL;
  const { loadPyodide } = await import(`${indexURL}pyodide.mjs`);
  const pyodide = await loadPyodide({ indexURL });
  await pyodide.loadPackage("micropip");

  const micropip = pyodide.pyimport("micropip");
  try {
    const wheels = manifest.packages.map((wheel) => new URL(wheel, manifestUrl).href);
    // micropip installs the wheels of one call concurrently and loads each wheel's extension
    // modules as it installs them. angr's extension needs the z3-solver wheel's libz3.so to be on
    // the filesystem by then, so install angr only after everything else is in place.
    const angrWheels = wheels.filter((wheel) => /\/angr-[^/]*\.whl$/.test(wheel));
    const dependencyWheels = wheels.filter((wheel) => !angrWheels.includes(wheel));
    await micropip.install(dependencyWheels, { keep_going: true });
    await micropip.install(angrWheels, { keep_going: true });
  } finally {
    micropip.destroy();
  }
  await pyodide.runPythonAsync("import angr");

  return pyodide;
}

function runtime(manifestUrl) {
  runtimePromise ??= initialize(manifestUrl);
  return runtimePromise;
}

async function analyze(pyodide, request) {
  const path = `/tmp/angr-upload-${++uploadCounter}`;
  pyodide.FS.writeFile(path, new Uint8Array(request.data));
  pyodide.globals.set("_angr_uploaded_path", path);
  pyodide.globals.set("_angr_build_cfg", request.cfg !== false);

  try {
    const result = await pyodide.runPythonAsync(`
import angr

def _angr_analyze(path, build_cfg):
    project = angr.Project(path, auto_load_libs=False)
    block = project.factory.block(project.entry)
    result = {
        "angrVersion": angr.__version__,
        "arch": project.arch.name,
        "entry": project.entry,
        "entryBlockSize": block.size,
        "entryInstructions": [str(insn) for insn in block.capstone.insns],
    }
    if build_cfg:
        cfg = project.analyses.CFGFast(normalize=True)
        result["cfgNodes"] = sum(1 for _ in cfg.graph.nodes())
        result["functions"] = sum(1 for _ in cfg.functions)
    return result

_angr_analyze(_angr_uploaded_path, _angr_build_cfg)
`);
    return convertResult(result);
  } finally {
    pyodide.runPython("globals().pop('_angr_analyze', None)");
    pyodide.globals.delete("_angr_uploaded_path");
    pyodide.globals.delete("_angr_build_cfg");
    pyodide.FS.unlink(path);
  }
}

self.addEventListener("message", async ({ data: request }) => {
  try {
    const pyodide = await runtime(request.manifestUrl);
    let result;

    if (request.type === "init") {
      result = convertResult(
        pyodide.runPython("{'version': angr.__version__}")
      );
    } else if (request.type === "analyze") {
      result = await analyze(pyodide, request);
    } else if (request.type === "run") {
      result = convertResult(await pyodide.runPythonAsync(request.code));
    } else {
      throw new Error(`Unknown angr worker request: ${request.type}`);
    }

    self.postMessage({ id: request.id, ok: true, result });
  } catch (error) {
    self.postMessage({ id: request.id, ok: false, error: error.stack ?? String(error) });
  }
});
