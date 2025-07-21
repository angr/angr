# pylint: disable=R0201,C0111,line-too-long,bad-builtin,expression-not-assigned,no-member
from __future__ import annotations

import struct
from unittest import TestCase

from archinfo import ArchAArch64
import angr
from angr.analyses import CFGFast, ReachingDefinitionsAnalysis
from angr.knowledge_plugins import Function
from angr.knowledge_plugins.key_definitions.atoms import Atom
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE


class TestRDARegressions(TestCase):
    """
    Test misc regressions for the ReachingDefinitionsAnalysis.
    """

    def test_load_multiple_concrete_addresses(self):
        """
        Foo
                                     **************************************************************
                                 *                                                            *
                                 * Member of: RCTActivityIndicatorViewManager                 *
                                 *                                                            *
                                 * -(void)set_animating:(id) forView:(id) withDefaultView:... *
                                 *                                                            *
                                 **************************************************************
                                 void __cdecl set_animating:forView:withDefaultView:(RCTA
                 void              <VOID>         <RETURN>
                 RCTActivityInd    x0:8           self
                 SEL               x1:8           selector
                 ID                x2:8           set_animating
                 ID                x3:8           view
                 ID                x4:8           defaultView
                 undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     10006a1a0(W),
                                                                                                       10006a268(*)
                 undefined8        Stack[-0x20]:8 local_20                                XREF[2]:     10006a19c(W),
                                                                                                       10006a26c(R)
                 undefined8        Stack[-0x30]:8 local_30                                XREF[2]:     10006a198(W),
                                                                                                       10006a270(R)
                 undefined8        Stack[-0x40]:8 local_40                                XREF[1]:     10006a194(W)
                                 RCTActivityIndicatorViewManager::set_animating  XREF[1]:     100216ba8(*)
          __text:10006a194 f8 5f bc a9     stp                x24,x23,[sp, #local_40]!
          __text:10006a198 f6 57 01 a9     stp                x22,x21,[sp, #local_30]
          __text:10006a19c f4 4f 02 a9     stp                x20,x19,[sp, #local_20]
          __text:10006a1a0 fd 7b 03 a9     stp                x29,x30,[sp, #local_10]
          __text:10006a1a4 fd c3 00 91     add                x29,sp,#0x30
          __text:10006a1a8 f5 03 04 aa     mov                x21,x4
          __text:10006a1ac f4 03 03 aa     mov                x20,x3
          __text:10006a1b0 e0 03 02 aa     mov                x0,x2
          __text:10006a1b4 eb 3d 04 94     bl                 __stubs::_objc_retain                            undefined _objc_retain()
          __text:10006a1b8 f3 03 00 aa     mov                x19,x0
          __text:10006a1bc e0 03 14 aa     mov                x0,x20
          __text:10006a1c0 e8 3d 04 94     bl                 __stubs::_objc_retain                            undefined _objc_retain()
          __text:10006a1c4 f4 03 00 aa     mov                x20,x0
          __text:10006a1c8 e0 03 15 aa     mov                x0,x21
          __text:10006a1cc e5 3d 04 94     bl                 __stubs::_objc_retain                            undefined _objc_retain()
          __text:10006a1d0 f5 03 00 aa     mov                x21,x0
          __text:10006a1d4 73 01 00 b4     cbz                x19,LAB_10006a200
          __text:10006a1d8 a8 0f 00 f0     adrp               x8,0x100261000
          __text:10006a1dc 00 0d 44 f9     ldr                x0=>objc::class_t::RCTConvert,[x8, #0x818]=>->   = 100264cc8
          __text:10006a1e0 88 0f 00 d0     adrp               x8,0x10025c000
          __text:10006a1e4 01 a9 47 f9     ldr                x1=>s_BOOL:_10018cc31,[x8, #0xf50]=>PTR_s_BOOL   = "BOOL:"
                                                                                                              = 10018cc31
          __text:10006a1e8 e2 03 13 aa     mov                x2,x19
          __text:10006a1ec d4 3d 04 94     bl                 __stubs::_objc_msgSend                           [UNNAMED BOOL:param_3]
          __text:10006a1f0 f6 03 00 aa     mov                x22,x0
          __text:10006a1f4 88 0f 00 f0     adrp               x8,0x10025d000
          __text:10006a1f8 17 f9 47 f9     ldr                x23,[x8, #0xff0]=>PTR_s_isAnimating_10025dff0    = 1001919d9
          __text:10006a1fc 07 00 00 14     b                  LAB_10006a218
                                 LAB_10006a200                                   XREF[1]:     10006a1d4(j)
          __text:10006a200 88 0f 00 f0     adrp               x8,0x10025d000
          __text:10006a204 17 f9 47 f9     ldr                x23,[x8, #0xff0]=>PTR_s_isAnimating_10025dff0    = 1001919d9
          __text:10006a208 e0 03 15 aa     mov                x0,x21
          __text:10006a20c e1 03 17 aa     mov                x1=>s_isAnimating_1001919d9,x23                  = "isAnimating"
          __text:10006a210 cb 3d 04 94     bl                 __stubs::_objc_msgSend                           [param_5 isAnimating]
          __text:10006a214 f6 03 00 aa     mov                x22,x0
                                 LAB_10006a218                                   XREF[1]:     10006a1fc(j)
          __text:10006a218 e0 03 14 aa     mov                x0,x20
          __text:10006a21c e1 03 17 aa     mov                x1=>s_isAnimating_1001919d9,x23                  = "isAnimating"
          __text:10006a220 c7 3d 04 94     bl                 __stubs::_objc_msgSend                           [param_4 isAnimating]
          __text:10006a224 c8 02 00 4a     eor                w8,w22,w0
          __text:10006a228 1f 05 00 71     cmp                w8,#0x1
          __text:10006a22c 41 01 00 54     b.ne               LAB_10006a254
          __text:10006a230 a8 0f 00 90     adrp               x8,0x10025e000
          __text:10006a234 08 61 00 91     add                x8,x8,#0x18
          __text:10006a238 a9 0f 00 90     adrp               x9,0x10025e000
          __text:10006a23c 29 81 00 91     add                x9,x9,#0x20
          __text:10006a240 df 02 00 71     cmp                w22,#0x0
          __text:10006a244 08 11 89 9a     csel               x8,x8,x9,ne
          __text:10006a248 01 01 40 f9     ldr                x1=>s_stopAnimating_100191a4c,[x8]=>PTR_s_stop   = "stopAnimating"
                                                                                                              = 100191a4c
          __text:10006a24c e0 03 14 aa     mov                x0,x20
          __text:10006a250 bb 3d 04 94     bl                 __stubs::_objc_msgSend                           [param_4 UNNAMED]
                                 LAB_10006a254                                   XREF[1]:     10006a22c(j)
          __text:10006a254 e0 03 15 aa     mov                x0,x21
          __text:10006a258 bf 3d 04 94     bl                 __stubs::_objc_release                           undefined _objc_release()
          __text:10006a25c e0 03 14 aa     mov                x0,x20
          __text:10006a260 bd 3d 04 94     bl                 __stubs::_objc_release                           undefined _objc_release()
          __text:10006a264 e0 03 13 aa     mov                x0,x19
          __text:10006a268 fd 7b 43 a9     ldp                x29=>local_10,x30,[sp, #0x30]
          __text:10006a26c f4 4f 42 a9     ldp                x20,x19,[sp, #local_20]
          __text:10006a270 f6 57 41 a9     ldp                x22,x21,[sp, #local_30]
          __text:10006a274 f8 5f c4 a8     ldp                x24,x23,[sp], #0x40
          __text:10006a278 b7 3d 04 14     b                  __stubs::_objc_release                           undefined _objc_release()
                                 -- Flow Override: CALL_RETURN (CALL_TERMINATOR)

        :return:
        """
        data = (
            b"\xf8\x5f\xbc\xa9"
            b"\xf6\x57\x01\xa9"
            b"\xf4\x4f\x02\xa9"
            b"\xfd\x7b\x03\xa9"
            b"\xfd\xc3\x00\x91"
            b"\xf5\x03\x04\xaa"
            b"\xf4\x03\x03\xaa"
            b"\xe0\x03\x02\xaa"
            b"\xeb\x3d\x04\x94"
            b"\xf3\x03\x00\xaa"
            b"\xe0\x03\x14\xaa"
            b"\xe8\x3d\x04\x94"
            b"\xf4\x03\x00\xaa"
            b"\xe0\x03\x15\xaa"
            b"\xe5\x3d\x04\x94"
            b"\xf5\x03\x00\xaa"
            b"\x73\x01\x00\xb4"
            b"\xa8\x0f\x00\xf0"
            b"\x00\x0d\x44\xf9"
            b"\x88\x0f\x00\xd0"
            b"\x01\xa9\x47\xf9"
            b"\xe2\x03\x13\xaa"
            b"\xd4\x3d\x04\x94"
            b"\xf6\x03\x00\xaa"
            b"\x88\x0f\x00\xf0"
            b"\x17\xf9\x47\xf9"
            b"\x07\x00\x00\x14"
            b"\x88\x0f\x00\xf0"
            b"\x17\xf9\x47\xf9"
            b"\xe0\x03\x15\xaa"
            b"\xe1\x03\x17\xaa"
            b"\xcb\x3d\x04\x94"
            b"\xf6\x03\x00\xaa"
            b"\xe0\x03\x14\xaa"
            b"\xe1\x03\x17\xaa"
            b"\xc7\x3d\x04\x94"
            b"\xc8\x02\x00\x4a"
            b"\x1f\x05\x00\x71"
            b"\x41\x01\x00\x54"
            b"\xa8\x0f\x00\x90"
            b"\x08\x61\x00\x91"
            b"\xa9\x0f\x00\x90"
            b"\x29\x81\x00\x91"
            b"\xdf\x02\x00\x71"
            b"\x08\x11\x89\x9a"
            b"\x01\x01\x40\xf9"
            b"\xe0\x03\x14\xaa"
            b"\xbb\x3d\x04\x94"
            b"\xe0\x03\x15\xaa"
            b"\xbf\x3d\x04\x94"
            b"\xe0\x03\x14\xaa"
            b"\xbd\x3d\x04\x94"
            b"\xe0\x03\x13\xaa"
            b"\xfd\x7b\x43\xa9"
            b"\xf4\x4f\x42\xa9"
            b"\xf6\x57\x41\xa9"
            b"\xf8\x5f\xc4\xa8"
            b"\xb7\x3d\x04\x14"
        )
        function_entry = 0x10006A194  # base10: 4295401876

        proj = angr.project.load_shellcode(data, ArchAArch64(), load_address=function_entry)

        proj.loader.memory.add_backer(0x10025E018, struct.pack("<Q", 0x100191A3D))
        proj.loader.memory.add_backer(0x10025E020, struct.pack("<Q", 0x100191A4C))

        proj.loader.memory.add_backer(0x100191A3D, b"startAnimating")
        proj.loader.memory.add_backer(0x100191A4C, b"stopAnimating")

        cfg = proj.analyses[CFGFast].prep()(function_starts=[function_entry], force_smart_scan=False)
        assert 0x10006A194 in cfg.functions

        function_to_analyze: Function = proj.kb.functions[function_entry]

        call_observation = ("insn", 0x10006A250, OP_BEFORE)

        rda = proj.analyses[ReachingDefinitionsAnalysis].prep()(
            function_to_analyze,
            observation_points=[call_observation],
        )

        observation = rda.observed_results[call_observation]
        selector = observation.get_values(Atom.reg("x1", arch=proj.arch))
        assert selector is not None
        assert (
            selector.one_value() is None
        ), f"There should be multiple concrete values for x1, not just one: {selector}"
        assert 0 in selector
        assert {bv.concrete_value for bv in selector[0]} == {
            0x100191A4C,
            0x100191A3D,
        }, f"Expected selector to contain the pointers to 'startAnimating' and 'stopAnimating' i.e. 0x100191A4C, 0x100191A3D, but got: {selector}"
