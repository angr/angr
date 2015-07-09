#!/usr/bin/env python
from .s_procedure import SimProcedure, SimProcedureError
import re
import simuvex
import logging

l = logging.getLogger("simuvex.parseformat")

class FormatParser(SimProcedure):
    """
    For SimProcedures relying on format strings.
    """

    # Basic conversion specifiers for format strings, mapped to Simuvex s_types
    # TODO: support for C and S that are deprecated.
    # TODO: We only consider POSIX locales here.
    basic_spec = {
        ('d', 'i') : ('int',),
        ('o', 'u', 'x', 'X') : ('unsigned', 'int'),
        ('e', 'E') : ('dword',),
        ('f', 'F') : ('dword',),
        ('g', 'G') : ('dword',),
        ('a', 'A') : ('dword',),
        ('c',) : ('char',),
        ('s',) : ('string',),
        ('p',) : ('uintptr_t',),
        ('n',) : ('uintptr_t',), # pointer to num bytes written so far
        ('m', '%') : None, # Those don't expect any argument
    }

    # Signedness of integers
    int_sign = {
        'signed': ['d', 'i'],
        'unsigned' : ['o', 'u', 'x', 'X']
    }

    # Length modifiers and how they apply to integer conversion (signed /
    # unsinged)
    int_len_mod = {
        'hh': ('char', 'uint8_t'),
        'h' : ('int16_t', 'uint16_t'),
        'l' : ('long', ('unsigned', 'long')),
        # FIXME: long long is 64bit according to stdint.h on Linux,  but that might not always be the case
        'll' : ('int64_t', 'uint64_t'),

        # FIXME: intmax_t seems to be always 64 bit, but not too sure
        'j' : ('int64_t', 'uint64_t'),
        'z' : ('ssize', 'size_t'), # TODO: implement in s_type
        't' : ('ptrdiff_t', 'ptrdiff_t'), # TODO: implement in s_type
    }

    # Types that are not known by Simuvex.s_types
    # Maps to (size, signedness)
    other_types = {
        ('dword',) : lambda _:(4, True),
        ('string',): lambda _:(0, True) # special value for strings, we need to count
    }

    # Those flags affect the formatting the output string
    flags = ['#', '0', r'\-', r' ', r'\+', r'\'', 'I']

    @property
    def _mod_spec(self):
        """
        Modified length specifiers: mapping between length modifiers and
        conversion specifiers.  This generates all the possibilities, i.e. hhd,
        etc.
       """
        mod_spec={}
        for mod, sizes in self.int_len_mod.iteritems():

            for conv in self.int_sign['signed']:
                mod_spec[mod + conv] = sizes[0]

            for conv in self.int_sign['unsigned']:
                mod_spec[mod + conv] = sizes[1]

        return mod_spec

    # Tricky stuff
    # Note that $ is not C99 compliant (but posix specific).
    tricks = ['*', '$']

    def _get_fmt(self, fmt):
        """
        Extract the actual formats from the format string @fmt
        Returns an array of formats.
        """

        # First, get rid of $
        s_fmt = re.sub('$', '', fmt)

        # Extract basic conversion modifiers from basic_spec.keys (tuples)
        basic_spec = [k for t in self.basic_spec.keys() for k in t]

        # All conversion specifiers, basic ones and appended to len modifiers
        all_spec = '(' + '|'.join(basic_spec) + '|' + '|'.join(self._mod_spec.keys()) + ')'

        # Build regex
        # FIXME: make sure the placement of * is correct
        r_flags = '[' + ''.join(self.flags) + ']*'
        s_re = '%' + r_flags + r'\.?\*?[0-9]*' + all_spec

        matching = []
        regex = re.compile(r"%s" % s_re)
        r = re.finditer(regex, s_fmt)
        for match in r:
            matching.append(match.group())

        return matching

    def _get_str_at(self, str_addr):

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        # Pointer to the string

        # FIXME: what should we do here ?
        if self.state.se.symbolic(str_addr):
            raise SimProcedureError("Symbolic pointer to (format) string :(")

        strlen = self.inline_call(strlen, str_addr).ret_expr
        if self.state.se.symbolic(strlen):
            raise SimProcedureError("Symbolic (format) string, game over :(")

        #TODO: we probably could do something more fine-grained here.
        return self.state.memory.load(str_addr, strlen)

    def _size(self, fmt):
        """
        From a format, returns the size to read from memory, as well as the
        signedness of this format
        """
        # First iterate through conversion specifiers that have been applied a
        # length modifier. E.g., %ld, %lu etc.
        for spec, type in self._mod_spec.iteritems():
            if spec in fmt:
                return self._lookup_size(type)

        # Then, iterate through (shorter) basic specifiers, e.g. %d, %l etc.
        for spec, type in self.basic_spec.iteritems():
            for s in spec:
                if s in fmt:
                    return self._lookup_size(type)

    def _lookup_size(self, type):
        """ Lookup the size and signedness of a given ctype """

        # We deal with strings separaterly, and consider their size 0 for now
        if type == ('string',):
            return (0, True)

        # Is that a Ctype ?
        elif type in simuvex.s_type._C_TYPE_TO_SIMTYPE.keys():
            s_type = simuvex.s_type._C_TYPE_TO_SIMTYPE[type](self.state.arch)

        # Or is it something else from ALL_TYPES ? (Like dword and stuff)
        elif type in simuvex.s_type.ALL_TYPES.keys():
            s_type = simuvex.s_type.ALL_TYPES[type](self.state.arch)

        else:
            raise SimProcedureError("This is a bug, we should know %s" % repr(type))

        return (s_type.size, s_type.signed)

    def _parse(self, fmt_idx):
        """
        Parse format strings.
        Returns: the format string in which format specifiers have been replaced
        with the actual content of arguments read from memory.

        @fmt_idx: index of the (pointer to the) format string in the arguments
        list.

        TODO: support for symbolic stuff
        """

        fmtstr_ptr = self.arg(fmt_idx)

        fmt_xpr = self._get_str_at(fmtstr_ptr)
        fmt = self.state.se.any_str(fmt_xpr)

        # Chop off everything from the format string except for the actual
        # formats of args
        args = self._get_fmt(fmt)

        # Fist arg is after the format string
        argno = 1 + fmt_idx
        l.debug("Fmt: %s ; Args: %s" % (fmt, repr(args)))

        for arg in args:

            # * basically shitfs arguments by one, considering that it happens
            # before the actual conversion specifier. FIXME: make sure that's
            # right

            # '*' it unpiles one argument off the list
            star = None
            if '*' in arg:
                star = int(self.state.se.any_int(self.arg(argno)))
                argno = argno + 1

            # Now, let's get a pointer to whatever this arg is
            ptr = self.arg(argno)

            # How much memory are we supposed to read here ?
            sz, signed = self._size(arg)

            if sz is None:
                raise SimProcedureError("Could not determine the size of %s" % arg)

            # A pointer is directly output. In this case we don't reference it
            # but directly print its address.
            if "p" in arg:
                xpr = ptr
                out = str(ptr)

            # In all other cases, we dereference a pointer and access the actual
            # data.

            # Strings
            elif sz == 0:
                xpr = self._get_str_at(ptr) # Concrete data we read
                out = self.state.se.any_str(xpr)
                sz = xpr.size()

            # Numeric values (passed as immediates)
            else:
                read = self.state.se.any_int(ptr)

                if read < 0 and signed == False:
                    read = read & (2^sz)

                # Let's hope python's interpretation of format strings doesn't
                # differ too much from printf's one.
                if star is not None:
                    # If the format containts '*', we need to pass it the
                    # corresponding argument
                    out = arg % (star, read)
                else:
                    out = arg % read

            l.debug("Arg: %s - read: %s" % (arg, out))
            argno = argno + 1

            # Replace format by actual data in format string
            fmt = re.sub(arg, out, fmt)

        # Return a bit vector value encoding the concrete string
        return self.state.BVV(fmt, len(fmt) + 1)
