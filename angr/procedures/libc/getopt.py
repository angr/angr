from __future__ import annotations

import logging

import angr
from angr import claripy

l = logging.getLogger(name=__name__)

# struct option { const char *name; int has_arg; int *flag; int val; }
_NO_ARGUMENT = 0
_REQUIRED_ARGUMENT = 1

# argv ordering, selected by a leading '+' or '-' in optstring
_REQUIRE_ORDER = 0
_PERMUTE = 1
_RETURN_IN_ORDER = 2

_DASH = ord("-")
_COLON = ord(":")
_QUESTION = ord("?")
_DONE = 0xFFFFFFFF  # -1


class _Unsupported(Exception):
    """A value the parser needs is symbolic or unterminated."""


class _GetOptBase(angr.SimProcedure):
    """
    glibc's getopt (posix/getopt.c: _getopt_internal_r and process_long_option) for concrete argv, optstring and
    longopts, including argv permutation. POSIXLY_CORRECT and the "W;" extension are not supported, and error
    messages are logged instead of printed. If anything the parser reads is symbolic, the call returns an
    unconstrained value and changes nothing; so does an unterminated string.

    The guest's optind, optarg and optopt are written through their loader symbols. glibc's private state, the
    position inside a group of short options and the operands skipped so far, is kept in SimStateLibc.
    """

    # pylint:disable=attribute-defined-outside-init

    def _getopt(self, argc, argv, optstring, longopts=None, longindex=None, long_only=False):
        try:
            return claripy.BVV(self._parse(argc, argv, optstring, longopts, longindex, long_only), 32)
        except _Unsupported:
            return claripy.BVS("getopt", 32)

    # ---- memory ----

    def _concrete(self, value):
        if self.state.solver.symbolic(value):
            raise _Unsupported
        return self.state.solver.eval(value)

    def _load(self, addr, size):
        return self._concrete(self.state.memory.load(addr, size, endness=self.state.arch.memory_endness))

    def _cstr(self, ptr, cap=4096):
        out = bytearray()
        for i in range(cap):
            b = self._concrete(self.state.memory.load(ptr + i, 1))
            if b == 0:
                return bytes(out)
            out.append(b)
        raise _Unsupported

    def _argp(self, i):
        if i not in self.argv_ptrs:
            self.argv_ptrs[i] = self._load(self.argv + i * self.state.arch.bytes, self.state.arch.bytes)
        return self.argv_ptrs[i]

    def _arg(self, i):
        return self._cstr(self._argp(i))

    def _nonoption(self, i):
        arg = self._arg(i)
        return len(arg) < 2 or arg[0] != _DASH

    def _global_addr(self, name):
        proj = self.project if self.project is not None else self.state.project
        sym = proj.loader.find_symbol(name) if proj is not None else None
        return sym.rebased_addr if sym is not None else None

    def _store(self, addr, value, bits):
        self.state.memory.store(
            addr,
            claripy.BVV(value, bits),
            endness=self.state.arch.memory_endness,
            inspect=False,
            disable_actions=True,
        )

    def _store_global(self, name, value, bits):
        addr = self._global_addr(name)
        if addr is not None:
            self._store(addr, value, bits)

    # ---- driver ----

    def _parse(self, argc, argv, optstring, longopts, longindex, long_only):
        self.argc = self._concrete(argc)
        self.argv = self._concrete(argv)
        optstring = self._cstr(self._concrete(optstring))
        self.longopts = self._concrete(longopts) if longopts is not None else 0
        self.longindex = self._concrete(longindex) if longindex is not None else 0
        self.long_only = long_only
        if self.argc < 1:
            return _DONE

        self.argv_ptrs = {}
        self.dirty = set()
        self.optarg = 0
        self.optopt = None

        libc = self.state.libc
        self.optind, self.nextchar = libc.getopt_optind, libc.getopt_nextchar
        self.first, self.last = libc.getopt_first_nonopt, libc.getopt_last_nonopt
        optind_addr = self._global_addr("optind")
        if optind_addr is not None:
            guest = self._load(optind_addr, 4)
            if guest == 0:
                # optind = 0 requests a full reset
                self.optind, self.nextchar, self.first, self.last = 1, 0, 1, 1
            elif guest != self.optind:
                self.optind, self.nextchar = guest, 0

        ordering = _PERMUTE
        if optstring[:1] == b"-":
            ordering = _RETURN_IN_ORDER
            optstring = optstring[1:]
        elif optstring[:1] == b"+":
            ordering = _REQUIRE_ORDER
            optstring = optstring[1:]
        self.optstring = optstring

        ret = self._next(ordering)

        for i in self.dirty:
            self._store(self.argv + i * self.state.arch.bytes, self.argv_ptrs[i], self.state.arch.bits)
        libc.getopt_optind, libc.getopt_nextchar = self.optind, self.nextchar
        libc.getopt_first_nonopt, libc.getopt_last_nonopt = self.first, self.last
        self._store_global("optind", self.optind, 32)
        self._store_global("optarg", self.optarg, self.state.arch.bits)
        if self.optopt is not None:
            self._store_global("optopt", self.optopt, 32)
        return ret

    def _error(self, optopt, ret=_QUESTION):
        l.debug("getopt: invalid option or missing argument (optopt %d)", optopt)
        self.optopt = optopt
        return ret

    def _missing_argument(self, optopt):
        return self._error(optopt, _COLON if self.optstring[:1] == b":" else _QUESTION)

    # ---- argv permutation ----

    def _exchange(self):
        """Move the skipped operands argv[first:last] behind the options argv[last:optind]."""
        ptrs = [self._argp(i) for i in range(self.first, self.optind)]
        split = self.last - self.first
        for i, ptr in enumerate(ptrs[split:] + ptrs[:split]):
            self.argv_ptrs[self.first + i] = ptr
            self.dirty.add(self.first + i)
        self.first += self.optind - self.last
        self.last = self.optind

    def _next(self, ordering):
        if self.nextchar == 0:
            # starting a new argv element
            self.last = min(self.last, self.optind)
            self.first = min(self.first, self.optind)

            if ordering == _PERMUTE:
                if self.first != self.last and self.last != self.optind:
                    self._exchange()
                elif self.last != self.optind:
                    self.first = self.optind
                while self.optind < self.argc and self._nonoption(self.optind):
                    self.optind += 1
                self.last = self.optind

            if self.optind < self.argc and self._arg(self.optind) == b"--":
                self.optind += 1
                if self.first != self.last and self.last != self.optind:
                    self._exchange()
                elif self.first == self.last:
                    self.first = self.optind
                self.last = self.argc
                self.optind = self.argc

            if self.optind >= self.argc:
                # leave optind on the first operand
                if self.first != self.last:
                    self.optind = self.first
                return _DONE

            if self._nonoption(self.optind):
                if ordering == _REQUIRE_ORDER:
                    return _DONE
                # RETURN_IN_ORDER: report the operand as the argument of option 1
                self.optarg = self._argp(self.optind)
                self.optind += 1
                return 1

            arg = self._arg(self.optind)
            if self.longopts:
                if arg[1] == _DASH:
                    return self._long(arg, 2)
                if self.long_only and (len(arg) > 2 or arg[1] not in self.optstring):
                    ret = self._long(arg, 1)
                    if ret is not None:
                        return ret
            self.nextchar = 1

        return self._short()

    # ---- options ----

    def _short(self):
        arg = self._arg(self.optind)
        c = arg[self.nextchar]
        self.nextchar += 1
        at_end = self.nextchar >= len(arg)
        if at_end:
            self.optind += 1

        idx = self.optstring.find(bytes([c]))
        if idx < 0 or c in (_COLON, ord(";")):
            if at_end:
                self.nextchar = 0
            return self._error(c)

        if self.optstring[idx + 1 : idx + 2] == b":":
            optional = self.optstring[idx + 2 : idx + 3] == b":"
            if not at_end:
                # the argument is the rest of this element
                self.optarg = self._argp(self.optind) + self.nextchar
                self.optind += 1
            elif not optional:
                if self.optind >= self.argc:
                    c = self._missing_argument(c)
                else:
                    self.optarg = self._argp(self.optind)
                    self.optind += 1
            self.nextchar = 0
        elif at_end:
            self.nextchar = 0
        return c

    def _longopts(self):
        """The longopts table as a list of (name, has_arg, flag, val)."""
        ps = self.state.arch.bytes
        options = []
        entry = self.longopts
        while True:
            name_ptr = self._load(entry, ps)
            if name_ptr == 0:
                return options
            options.append(
                (
                    self._cstr(name_ptr),
                    self._load(entry + ps, 4),
                    self._load(entry + 2 * ps, ps),
                    self._load(entry + 3 * ps, 4),
                )
            )
            entry += 4 * ps

    def _long(self, arg, prefix_len):
        """
        Match "--name[=value]" (or "-name" for getopt_long_only). Returns None when getopt_long_only should fall
        back to a short option.
        """
        name, eq, _ = arg[prefix_len:].partition(b"=")
        options = self._longopts()

        found = next((i for i, o in enumerate(options) if o[0] == name), None)
        if found is None:
            ambiguous = False
            for i, o in enumerate(options):
                if o[0].startswith(name):
                    if found is None:
                        found = i
                    elif self.long_only or o[1:] != options[found][1:]:
                        # prefixes of options that behave the same, such as aliases, are not ambiguous
                        ambiguous = True
            if ambiguous:
                self.optind += 1
                return self._error(0)

        if found is None:
            if not self.long_only or arg[1] == _DASH or arg[1] not in self.optstring:
                self.optind += 1
                return self._error(0)
            return None

        _, has_arg, flag, val = options[found]
        self.optind += 1
        if eq:
            if has_arg == _NO_ARGUMENT:
                return self._error(val)
            self.optarg = self._argp(self.optind - 1) + prefix_len + len(name) + 1
        elif has_arg == _REQUIRED_ARGUMENT:
            if self.optind >= self.argc:
                return self._missing_argument(val)
            self.optarg = self._argp(self.optind)
            self.optind += 1

        if self.longindex:
            self._store(self.longindex, found, 32)
        if flag:
            self._store(flag, val, 32)
            return 0
        return val


class getopt(_GetOptBase):
    # pylint:disable=arguments-differ
    def run(self, argc, argv, optstring):
        return self._getopt(argc, argv, optstring)


class getopt_long(_GetOptBase):
    # pylint:disable=arguments-differ
    def run(self, argc, argv, optstring, longopts, longindex):
        return self._getopt(argc, argv, optstring, longopts=longopts, longindex=longindex)


class getopt_long_only(_GetOptBase):
    # pylint:disable=arguments-differ
    def run(self, argc, argv, optstring, longopts, longindex):
        return self._getopt(argc, argv, optstring, longopts=longopts, longindex=longindex, long_only=True)
