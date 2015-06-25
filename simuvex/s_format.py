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
        ('p',) : ('uint64_t,'), # pointer TODO: Check with John
        ('n',) : ('uint64_t',), # pointer to num bytes written so far
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
    other_types = {
        ('dword',) : lambda _:4,
        ('ptrdiff_t',): lambda arch: arch.bits,
        ('size_t',): lambda arch: arch.bits,
        ('ssize_t',): lambda arch: arch.bits,
        ('string',): lambda _:0 # special value for strings, we need to count
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

    def _fetch_str_bytes(self, addr, offset=0):
        """
        Get a 10 byte str from memory at @addr + @offset
        We assume we are dealing with concrete stuff here.
        """
        xpr = self.state.mem_expr(addr + offset, 10)
        val = self.state.se.any_str(xpr)
        return val

    def _get_str(self, addr):
        """
        Get a string from memory starting at @addr.
        Stop when \n is encountered.
        """
        offset = 0
        fmt=""
        # We don't wanna go more than 1K ahead.
        while offset < 1024:
            fmt = fmt + self._fetch_str_bytes(addr, offset)

            # Lookup by increments of 10
            offset = offset + 10
            parsed = re.findall(r'.*\x00', fmt)

            # findall returns an array, we only care about the first string.
            if len(parsed) > 0:
                return parsed[0]

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
        str_xpr = self.state.mem_expr(str_addr, strlen)
        return self.state.se.any_str(str_xpr)


    def _size(self, fmt):
        """
        From a format, returns the size to read from memory.
        """
        # First iterate through conversion specifiers that have been applied a
        # length modifier.
        for spec, type in self._mod_spec.iteritems():
            if spec in fmt:
                if type in self.other_types.keys():
                    # If we found it, we translate the type into a size
                    return self.other_types[type](self.state.arch)
                else:
                    return simuvex.s_type._C_TYPE_TO_SIMTYPE[type](self.state.arch).size

        for spec, type in self.basic_spec.iteritems():
            for s in spec:
                if s in fmt:
                    if type in self.other_types.keys():
                        return self.other_types[type](self.state.arch)
                    else:
                        return simuvex.s_type._C_TYPE_TO_SIMTYPE[type](self.state.arch).size

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

        fmt = self._get_str_at(fmtstr_ptr)

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
            if '*' in arg:
                argno = argno + 1

            # Now, let's get a pointer to whatever this arg is
            ptr = self.arg(argno)

            # How much memory are we supposed to read here ?
            sz = self._size(arg)

            if sz is None:
                raise SimProcedureError("Could not determine the size of %s" % arg)

            # A pointer is directly output. In this case we don't reference it
            # but directly print its address.
            if "p" in arg:
                xpr = ptr
                read = str(ptr)

            # In all other cases, we dereference a pointer and access the actual
            # data.

            # Strings
            elif sz == 0:
                read = self._get_str(ptr) # Concrete data we read
                sz = len(read)
                xpr = self.state.mem_expr(ptr, sz)

            else:
                xpr = self.state.mem_expr(ptr, sz)
                read = str(self.state.se.any_int(xpr))

            l.debug("Arg: %s - read: %s" % (arg,read))
            argno = argno + 1

            # Replace format by actual data in format string
            fmt = re.sub(arg, read, fmt)

        # Return a bit vector value encoding the concrete string
        return self.state.BVV(fmt, len(fmt) + 1)
