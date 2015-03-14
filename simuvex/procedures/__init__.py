import os
import sys
from collections import defaultdict
import importlib

import logging
l = logging.getLogger('simuvex.procedures')

# Import all classes under the current directory, and group them based on
# lib names.
SimProcedures = defaultdict(dict)
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = []
skip_procs = [ ]

for lib_module_name in [f for f in os.listdir(path) if f != "__init__.py" and f not in skip_dirs]:
    if not os.path.isdir(os.path.join(path, lib_module_name)):
        l.debug("Not a dir: %s", lib_module_name)
        continue
    l.debug("Loading %s", lib_module_name)

    libname = lib_module_name.replace("___", ".")
    lib_path = os.path.join(path, lib_module_name)

    try:
        lib_module = importlib.import_module(".%s" % lib_module_name, 'simuvex.procedures')
    except ImportError:
        l.warning("Unable to import (possible) SimProcedure library %s", lib_module_name, exc_info=True)
        continue

    for proc_module_name in [f[: -3] for f in os.listdir(lib_path) if f.endswith(".py")]:
        if proc_module_name == '__init__' or proc_module_name in skip_procs:
            continue

        try:
            proc_module = importlib.import_module(".%s.%s" % (lib_module_name, proc_module_name), 'simuvex.procedures')
        except ImportError:
            l.warning("Unable to import procedure %s from SimProcedure library %s", proc_module_name, lib_module_name, exc_info=True)
            continue

        classes = [ getattr(proc_module, x) for x in dir(proc_module) if isinstance(getattr(proc_module, x), type) ]
        for class_ in classes:
            SimProcedures[libname][class_.__name__] = class_
