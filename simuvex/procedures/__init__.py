import os
import sys
from collections import defaultdict
import imp

# Import all classes under the current directory, and group them based on
# lib names.
SimProcedures = defaultdict(dict)
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = []

for libname in [f for f in os.listdir(path) if f != "__init__.py" and f not in skip_dirs]:
    lib_path = os.path.join(path, libname)
    libname = libname.replace("___", ".")
    if not os.path.isdir(lib_path):
        continue
    for py in [f[: -3] for f in os.listdir(lib_path) if f.endswith(".py")]:
        module_file_path = os.path.join(lib_path, py) + ".py"
        with open(module_file_path) as module_file:
            mod = imp.load_module(py, module_file, module_file_path,
                         (".py", "rb", imp.PY_SOURCE))
            if py == '__init__':
                continue

            classes = [getattr(mod, x) for x in dir(mod)
                        if isinstance(getattr(mod, x), type)]
            for class_ in classes:
                SimProcedures[libname][class_.__name__] = class_
