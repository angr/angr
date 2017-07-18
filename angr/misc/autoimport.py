import os
import importlib
import logging

l = logging.getLogger('angr.misc.autoimport')

def auto_import_packages(base_module, base_path, ignore_dirs=(), ignore_files=(), scan_modules=True):
    for lib_module_name in os.listdir(base_path):
        if lib_module_name in ignore_dirs:
            continue

        lib_path = os.path.join(base_path, lib_module_name)
        if not os.path.isdir(lib_path):
            l.debug("Not a dir: %s", lib_module_name)
            continue

        l.debug("Loading %s.%s", base_module, lib_module_name)

        try:
            package = importlib.import_module(".%s" % lib_module_name, base_module)
        except ImportError:
            l.warning("Unable to autoimport package %s.%s", base_module, lib_module_name, exc_info=True)
        else:
            if scan_modules:
                for name, mod in auto_import_modules('%s.%s' % (base_module, lib_module_name), lib_path, ignore_files=ignore_files):
                    if name not in dir(package):
                        setattr(package, name, mod)
            yield lib_module_name, package

def auto_import_modules(base_module, base_path, ignore_files=()):
    for proc_file_name in os.listdir(base_path):
        if not proc_file_name.endswith('.py'):
            continue
        if proc_file_name in ignore_files or proc_file_name == '__init__.py':
            continue
        proc_module_name = proc_file_name[:-3]

        try:
            proc_module = importlib.import_module(".%s" % proc_module_name, base_module)
        except ImportError:
            l.warning("Unable to autoimport module %s.%s", base_module, proc_module_name, exc_info=True)
            continue
        else:
            yield proc_module_name, proc_module

def filter_module(mod, type_req=None, subclass_req=None):
    for name in dir(mod):
        val = getattr(mod, name)
        if type_req is not None and not isinstance(val, type_req):
            continue
        if subclass_req is not None and not issubclass(val, subclass_req):
            continue
        yield name, val
