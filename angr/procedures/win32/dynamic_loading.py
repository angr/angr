import angr
import claripy
import logging

l = logging.getLogger(name=__name__)


class LoadLibraryA(angr.SimProcedure):
    def run(self, lib_ptr):
        lib = self.state.mem[lib_ptr].string.concrete.decode("utf-8")
        return self.load(lib)

    def load(self, lib):
        if "." not in lib:
            lib += ".dll"
        loaded = self.project.loader.dynamic_load(lib)
        if loaded is None:
            l.debug("LoadLibrary: Could not load %s", lib)
            return 0

        # Add simprocedures
        for obj in loaded:
            self.register(obj)

        l.debug("LoadLibrary: Loaded %s", lib)
        return self.project.loader.find_object(lib).mapped_base

    def register(self, obj):  # can be overridden for instrumentation
        self.project._register_object(obj, obj.arch)


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
        lib_handle = self.state.solver.eval(lib_handle)

        if lib_handle == 0:
            obj = self.project.loader.main_object
        else:
            for obj in self.project.loader.all_pe_objects:
                if obj.mapped_base == lib_handle:
                    break
            else:
                l.warning("GetProcAddress: invalid library handle %s", lib_handle)
                return 0

        if claripy.is_true(name_addr < 0x10000):
            # this matches the bogus name specified in the loader...
            ordinal = self.state.solver.eval(name_addr)
            name = "ordinal.%d.%s" % (ordinal, obj.provides)
        else:
            name = self.state.mem[name_addr].string.concrete.decode("utf-8")

        full_name = f"{obj.provides}.{name}"
        self.procs.add(full_name)

        sym = obj.get_symbol(name)
        if sym is None and name.endswith("@"):
            # There seems to be some mangling parsing being done in the linker?
            # I don't know what I'm doing
            for suffix in ["Z", "XZ"]:
                sym = obj.get_symbol(name + suffix)
                if sym is not None:
                    name = name + suffix
                    break

        if sym is None:
            l.info("GetProcAddress: object %s does not contain %s", obj.provides, name)
            return 0

        sym = sym.resolve_forwarder()
        if sym is None:
            l.warning("GetProcAddress: forwarding failed for %s from %s", name, obj.provides)
            return 0

        name = sym.name  # fix ordinal names
        full_name = f"{obj.provides}.{name}"
        self.procs.add(full_name)

        l.debug("GetProcAddress: Imported %s (%#x) from %s", name, sym.rebased_addr, obj.provides)
        return sym.rebased_addr

    KEY = "dynamically_loaded_procedures"

    @property
    def procs(self):
        try:
            return self.state.globals[self.KEY]
        except KeyError:
            x = set()
            self.state.globals[self.KEY] = x
            return x
