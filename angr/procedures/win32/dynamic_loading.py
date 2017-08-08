import angr
import claripy
import logging

l = logging.getLogger('angr.procedures.win32.dynamic_loading')

class LoadLibraryA(angr.SimProcedure):
    def run(self, lib_ptr):
        lib = self.state.mem[lib_ptr].string.concrete
        return self.load(lib)

    def load(self, lib):
        loaded = self.project.loader.dynamic_load(lib)
        if loaded is None:
            return 0

        # Add simprocedures
        for obj in loaded:
            self.register(obj)

        return self.project.loader.find_object(lib).mapped_base

    def register(self, obj): # can be overridden for instrumentation
        self.project._register_object(obj)

class LoadLibraryExW(LoadLibraryA):
    def run(self, lib_ptr, flag1, flag2):
        lib = self.state.mem[lib_ptr].wstring.concrete
        return self.load(lib)

# if you subclass LoadLibraryA to provide register, you can implement LoadLibraryExW by making an empty class that just
# subclasses your special procedure and LoadLibraryExW


class GetProcAddress(angr.SimProcedure):
    def run(self, lib_handle, name_addr):
        if lib_handle.symbolic:
            raise angr.errors.SimValueError("GetProcAddress called with symbolic library handle %s" % lib_handle)
        lib_handle = self.state.se.any_int(lib_handle)

        for obj in self.project.loader.all_pe_objects:
            if obj.mapped_base == lib_handle:
                break
        else:
            l.warning("GetProcAddress: invalid library handle %s", lib_handle)
            return 0

        if claripy.is_true(name_addr < 0x10000):
            # this matches the bogus name specified in the loader...
            name = 'ordinal.%d' % self.state.se.any_int(name_addr)
        else:
            name = self.state.mem[name_addr].string.concrete
        full_name = '%s.%s' % (obj.provides, name)
        self.procs.add(full_name)

        sym = obj.get_symbol(name)
        if sym is None:
            l.warning("GetProcAddress: object %s does not contain %s", obj.provides, name)
        return sym.rebased_addr

    KEY = 'dynamically_loaded_procedures'
    @property
    def procs(self):
        try:
            return self.state.globals[self.KEY]
        except KeyError:
            x = set()
            self.state.globals[self.KEY] = x
            return x