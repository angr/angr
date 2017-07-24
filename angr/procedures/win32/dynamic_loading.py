import angr
import claripy


class LoadLibraryA(angr.SimProcedure):
    def run(self, lib_ptr):
        lib = self.state.mem[lib_ptr].string.concrete
        return self.register(lib)

    KEY = 'dynamically_loaded_libs'
    @property
    def loaded(self):
        try:
            return self.state.globals[self.KEY]
        except KeyError:
            x = {}
            self.state.globals[self.KEY] = x
            return x

    def register(self, lib):
        try:
            return [key for key, val in self.loaded.items() if val == lib][0]
        except IndexError:
            pass

        key = len(self.loaded) + 1
        self.loaded[key] = lib
        return key

class LoadLibraryExW(LoadLibraryA):
    def run(self, lib_ptr, flag1, flag2):
        lib = self.state.mem[lib_ptr].wstring.concrete
        return self.register(lib)


class GetProcAddress(angr.SimProcedure):
    def run(self, lib_key, name_addr):
        if lib_key.symbolic:
            raise angr.errors.SimValueError("GetProcAddress called with symbolic library handle %s" % lib_key)

        lib_key = self.state.se.any_int(lib_key)

        if lib_key not in self.loaded:
            raise angr.errors.SimValueError("GetProcAddress called with invalid library handle %s" % lib_key)

        lib_name = self.loaded[lib_key]
        if claripy.is_true(name_addr < 0x10000):
            # IT'S AN ORDINAL IMPORT
            name = '[ordinal %#x]' % self.state.se.any_int(name_addr)
        else:
            name = self.state.mem[name_addr].string.concrete
        full_name = '%s.%s' % (lib_name, name)
        self.procs.add(full_name)

        addr = self.project._extern_obj.get_pseudo_addr(full_name)
        if not self.project.is_hooked(addr):
            return_val = None
            num_args = 0
            if name == 'InitializeCriticalSectionEx':
                num_args = 3
                return_val = 1
            elif name == 'FlsAlloc':
                num_args = 1
                return_val = 1
            elif name == 'FlsSetValue':
                num_args = 2
                return_val = 1

            cc = self.project.factory.cc_from_arg_kinds([False]*num_args)
            self.project.hook(addr, StubCall(cc=cc, resolves=full_name, return_val=return_val))
        return addr

    @property
    def loaded(self):
        try:
            return self.state.globals[LoadLibraryA.KEY]
        except KeyError:
            x = {}
            self.state.globals[LoadLibraryA.KEY] = x
            return x

    KEY = 'dynamically_loaded_procedures'
    @property
    def procs(self):
        try:
            return self.state.globals[self.KEY]
        except KeyError:
            x = set()
            self.state.globals[self.KEY] = x
            return x
