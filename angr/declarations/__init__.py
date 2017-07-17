
from .sim_declarations import SimDeclarations
from .libc import libc


class SimDeclarationStorage(object):
    def __init__(self):
        self._declarations = { }
        self._alternative_names = { }

    def add_declarations(self, decls):
        self._declarations[decls.library_name] = decls
        for alt_name in decls.alternative_names:
            self._alternative_names[alt_name] = decls.library_name

    def get_declarations(self, lib_name):
        if lib_name in self._alternative_names:
            lib_name = self._alternative_names[lib_name]

        if lib_name in self._declarations:
            return self._declarations[lib_name]

        return None

    def __contains__(self, lib_name):
        return self.get_declarations(lib_name) is not None

    def __getitem__(self, lib_name):
        decls = self.get_declarations(lib_name)
        if decls is None:
            raise KeyError('Declarations of library %s do not exist.' % lib_name)

        return decls


SIM_DECLARATIONS = SimDeclarationStorage()

SIM_DECLARATIONS.add_declarations(libc)
