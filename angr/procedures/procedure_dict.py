import importlib
import logging
import os
from collections import defaultdict

l = logging.getLogger("angr.procedures.procedure_dict")

from ..sim_procedure import SimProcedure

# Import all classes under the current directory, and group them based on
# lib names.
SIM_PROCEDURES = defaultdict(dict)
path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = ['__pycache__', 'definitions']
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
        lib_module = importlib.import_module(".%s" % lib_module_name, 'angr.procedures')
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
            proc_module = importlib.import_module(".%s.%s" % (lib_module_name, proc_module_name), 'angr.procedures')
        except ImportError:
            l.warning("Unable to import procedure %s from SimProcedure library %s", proc_module_name, lib_module_name, exc_info=True)
            continue

        for attr_name in dir(proc_module):
            attr = getattr(proc_module, attr_name)
            if isinstance(attr, type) and issubclass(attr, SimProcedure):
                SIM_PROCEDURES[libname][attr_name] = attr

class _SimProcedures(object):
    def __getitem__(self, k):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        return SIM_PROCEDURES[k]

    def __setitem__(self, k, v):
        l.critical("the SimProcedures dictionary is DEPRECATED. Please use the angr.SIM_PROCEDURES global dict instead.")
        SIM_PROCEDURES[k] = v
SimProcedures = _SimProcedures()
