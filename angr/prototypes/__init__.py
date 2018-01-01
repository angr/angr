
from .sim_prototypes import SimPrototypes
from .libc import libc


class SimPrototypeStorage(object):
    def __init__(self):
        self._prototypes = { }
        self._alternative_names = { }

    def add_prototypes(self, decls):
        self._prototypes[decls.library_name] = decls
        for alt_name in decls.alternative_names:
            self._alternative_names[alt_name] = decls.library_name

    def get_prototypes(self, lib_name):
        if lib_name in self._alternative_names:
            lib_name = self._alternative_names[lib_name]

        if lib_name in self._prototypes:
            return self._prototypes[lib_name]

        return None

    def __contains__(self, lib_name):
        return self.get_prototypes(lib_name) is not None

    def __getitem__(self, lib_name):
        decls = self.get_prototypes(lib_name)
        if decls is None:
            raise KeyError('Prototypes of library %s do not exist.' % lib_name)

        return decls


SIM_PROTOTYPES = SimPrototypeStorage()

SIM_PROTOTYPES.add_prototypes(libc)
