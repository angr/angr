#!/usr/bin/env python
import logging

l = logging.getLogger("memory_dict")
l.setLevel(logging.DEBUG)

class MemoryDict(dict):
        def __init__(self, infobin={}):
                self.__infobin = dict(infobin)
                super(MemoryDict, self).__init__()

        def __missing__(self, addr):
                sbin = None

                # by default ida set not found addresses to 255
                self.__setitem__(addr, 255)

                # look into the ghost memory
                for b in self.__infobin.itervalues():
                        r = b.get_range_addr()
                        if addr >= r[0] and addr <= r[1]:
                                sbin = b
                                break
                if sbin:
                        l.debug("Address %s is in ghost memory" %addr)
                        ida = sbin.get_ida()
                        sym_name = sbin.get_name_by_plt_addr(addr)

                        # plt_addr
                        if sym_name: # must solve the link
                                l.debug("Extern symbol, fixing plt entry")
                                jmp_addr = self.__infobin[sbin[sym_name].extrn_lib_name][sym_name].addr
                                assert jmp_addr, "Extern function never called, please report this"
                                size = ida.idautils.DecodeInstruction(sbin[sym_name].addr).size * 8
                                assert  size >= jmp_addr.bit_length(), "Address inexpectedly too long"
                                cnt = jmp_addr
                                for off in range(0, size / 8):
                                    cell = (cnt & (0xFF << (off*8)) >> (off*8))
                                    self.__setitem__(addr + off, cell)
                        else:
                                self.__setitem__(addr, ida.idaapi.get_byte(addr))

                return self.__getitem__(addr)

        def functions(self):
                #FIXME use a dict as in iterfunctions
                func = {}
                for bin in self.__infobin.itervalues():
                        ida = bin.get_ida()
                        namebin = ida.get_filename()
                        func[namebin] = []
                        for f_start in ida.idautils.Functions():
                                f = ida.idaapi.get_func(f_start)
                                func[namebin].append([f_start, (f.endEA - f.startEA)])
                return func

        def iterfunctions(self):
                for bin in self.__infobin.itervalues():
                        ida = bin.get_ida()
                        namebin = ida.get_filename()
                        for f_start in ida.idautils.Functions():
                                f = ida.idaapi.get_func(f_start)
                                assert f.startEA == f_start, "WHHAAAAAT??"
                                yield {'lib':namebin, 'start':f_start, 'size':(f.endEA - f.startEA + 1)}
