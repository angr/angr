
import pyvex
import archinfo

import ailment


def test_convert_from_irsb():

    irsb = pyvex.IRSB("\x48\x55", 0, archinfo.arch_from_id('AMD64'))

    ablock = ailment.IRSBConverter.convert(irsb)

    print str(ablock)

if __name__ == "__main__":
    test_convert_from_irsb()
