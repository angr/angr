import angr

######################################
# __ctype_toupper_loc
######################################

class __ctype_toupper_loc(angr.SimProcedure):
    """
    Following is the description from linuxfoundation.org:

    The __ctype_toupper_loc() function shall return a pointer into an array
    of characters in the current locale that contains upper case equivalents
    for each character in the current character set. The array shall contain
    a total of 384 characters, and can be indexed with any signed or unsigned
    char (i.e. with an index value between -128 and 255). If the application
    is multithreaded, the array shall be local to the current thread.

    This interface is not in the source standard; it is only in the binary
    standard.
    """

    def run(self):

        table_ptr = self.state.libc.ctype_toupper_loc_table_ptr

        return table_ptr
