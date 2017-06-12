import os
import sys
from collections import defaultdict
import importlib

import logging
l = logging.getLogger('simuvex.procedures')

from .. import SimProcedure

# Import all classes under the current directory, and group them based on
# lib names.
SimProcedures = defaultdict(dict)
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = ['__init__.py', '__pycache__']
skip_procs = ['__init__']

for lib_module_name in os.listdir(path):
    if lib_module_name in skip_dirs:
        continue

    lib_path = os.path.join(path, lib_module_name)
    if not os.path.isdir(os.path.join(path, lib_module_name)):
        l.debug("Not a dir: %s", lib_module_name)
        continue

    l.debug("Loading %s", lib_module_name)
    libname = lib_module_name.replace("___", ".")

    try:
        lib_module = importlib.import_module(".%s" % lib_module_name, 'simuvex.procedures')
    except ImportError:
        l.warning("Unable to import (possible) SimProcedure library %s", lib_module_name, exc_info=True)
        continue

    for proc_file_name in os.listdir(lib_path):
        if not proc_file_name.endswith('.py'):
            continue
        proc_module_name = proc_file_name[:-3]
        if proc_module_name in skip_procs:
            continue

        try:
            proc_module = importlib.import_module(".%s.%s" % (lib_module_name, proc_module_name), 'simuvex.procedures')
        except ImportError:
            l.warning("Unable to import procedure %s from SimProcedure library %s", proc_module_name, lib_module_name, exc_info=True)
            continue

        for attr_name in dir(proc_module):
            attr = getattr(proc_module, attr_name)
            if isinstance(attr, type) and issubclass(attr, SimProcedure):
                SimProcedures[libname][attr_name] = attr
