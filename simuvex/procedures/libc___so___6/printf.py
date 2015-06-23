import simuvex
import logging
from simuvex.s_procedure import SimProcedureError
import re

l = logging.getLogger("simuvex.procedures.libc_so_6.printf")

######################################
# _printf
######################################

class printf(simuvex.SimProcedure):

    # Basic conversion specifiers for format strings, mapped to Simuvex s_types
    # TODO: support for C and S that are deprecated.
    # TODO: We only consider POSIX locales here.
    basic_conv = {
        ('d', 'i') : 'int',
        ('o', 'u', 'x', 'X') : ('unsigned int'),
        ('e', 'E') : 'dword',
        ('f', 'F') : 'dword',
        ('g', 'G') : 'dword',
        ('a', 'A') : 'dword',
        ('c',) : 'char',
        ('s',) : 'string',
        ('p',) : 'uint64_t', # pointer TODO: Check with John
        ('n',) : 'uint64_t', # pointer to num bytes written so far
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

    # Those flags affect the formatting the output string
    flags = ['#', '0', r'\-', r' ', r'\+', r'\'', 'I']

    @property
    def _moded_conv(self):
        """
        Mapping between len modifiers and conversion specifiers.
        This generates all the possibilities, i.e. hhd, etc.
       """
        moded_conv={}
        for mod, sizes in self.int_len_mod.iteritems():

            for conv in self.int_sign['signed']:
                moded_conv[mod + conv] = sizes[0]

            for conv in self.int_sign['unsigned']:
                moded_conv[mod + conv] = sizes[1]

        return moded_conv

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

        # Extract basic conversion modifiers from basic_conv.keys (tuples)
        basic_conv = [k for t in self.basic_conv.keys() for k in t]

        # All conversion specifiers, basic ones and appended to len modifiers
        all_conv = '(' + '|'.join(basic_conv) + '|' + '|'.join(self._moded_conv.keys()) + ')'

        # Build regex
        # FIXME: make sure the placement of * is correct
        r_flags = '[' + ''.join(self.flags) + ']*'
        s_re = '%' + r_flags + r'\.?\*?[0-9]*' + all_conv

        regex = re.compile(r"%s" % s_re)
        r = re.search(regex, s_fmt)
        return r.group()

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

    def run(self):

        # Pointer to the format string
        fmtstr_ptr = self.arg(0)

        if self.state.se.symbolic(fmtstr_ptr):
            raise SimProcedureError("Symbolic pointer to format string :(")

        #addr = self.state.se.any_int(fmtstr_ptr)
        fmt = self._get_str(fmtstr_ptr)

        if self.state.se.symbolic(fmt):
            raise SimProcedureError("Symbolic format string, game over :(")

        # Chop off everything from the format string except for the actual
        # formats of args
        args = self._get_fmt(fmt)

        # We start at 1 as the first argument is the format string iteself
        argno = 1
        l.debug("Fmt: %s ; Args: %s" % (fmt, repr(args)))
        for a_fmt in args:
            l.debug("Got: %s" % repr(a_fmt))

            # * basically shitfs arguments by one, considering that it happens
            # before the actual conversion specifier. FIXME: make sure that's
            # right
            if '*' in a_fmt:
                argno = argno + 1

            # Now, let's get a pointer to whatever this arg is
            ptr = self.arg(argno)

            # How much memory are we supposed to read here ?
            if a_fmt == "%c":
                xpr = self.state.mem_expr(ptr,1)
                #import pdb; pdb.set_trace()
                #char = self.state.se.any_str(xpr)

            elif a_fmt == "%s":
                xpr = self.state.mem[ptr:].string

            for spec, size in self._moded_conv.iteritems():
                l.debug("fmt: %s/%s" % (spec, size))
                if spec in a_fmt:
                    s_type = simuvex.s_type._C_TYPE_TO_SIMTYPE[size]
                    import pdb; pdb.set_trace()
                    xpr = self.state.mem_expr(ptr, size)

            else:
                raise Exception("Unknown format %s" % repr(a_fmt))

            argno = argno + 1


        # This function returns
        # Add another exit to the retn_addr that is at the top of the stack now
        self.ret()
        # l.debug("Got return address for %s: 0x%08x.", __file__, self._exits[0].concretize())
