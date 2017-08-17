# This module contains enums for constants used by angr

class endness:
    """ Endness specifies the byte order for integer values

    :cvar LE:      little endian, least significant byte is stored at lowest address
    :cvar BE:      big endian, most significant byte is stored at lowest address 
    """
    LE = "Iend_LE"
    BE = "Iend_BE"
