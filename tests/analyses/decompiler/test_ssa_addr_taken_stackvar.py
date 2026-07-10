#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr


class TestSSAAddrTakenStackVar(unittest.TestCase):
    """
    Taking the address of a stack slot (e.g. passing ``&local`` to a callee) requires the slot to have a corresponding
    virtual variable that the address expression (``&local``) can reference.
    """

    # The blob below is from a 32-bit function (from a real binary) that takes the address of a stack slot ([ebp-0x38])
    # and passes it to multiple calls.
    #
    #                                     46ad1f  mov     edi, edi
    #                                     46ad21  push    ebp
    #                                     46ad22  mov     ebp, esp
    #                                     46ad24  sub     esp, 0x44
    #                                     46ad27  mov     eax, dword ptr [0x49f100]
    #                                     46ad2c  xor     eax, ebp
    #                                     46ad2e  mov     dword ptr [ebp-0x4], eax
    #                                     46ad31  mov     eax, dword ptr [ebp+0xc]
    #                                     46ad34  push    ebx
    #                                     46ad35  push    esi
    #                                     46ad36  mov     esi, dword ptr [ebp+0x8]
    #                                     46ad39  xor     ebx, ebx
    #                                     46ad3b  push    edi
    #                                     46ad3c  push    0x1ca
    #                                     46ad41  push    ebx
    #                                     46ad42  push    esi
    #                                     46ad43  mov     dword ptr [ebp-0x44], esi
    #                                     46ad46  mov     dword ptr [ebp-0x3c], eax
    #                                     46ad49  call    0x430430
    #
    #                                     46ad4e  mov     edx, dword ptr [ebp-0x3c]
    #                                     46ad51  lea     ecx, [ebp-0x30]
    #                                     46ad54  add     esp, 0xc
    #                                     46ad57  mov     dword ptr [ebp-0x38], ecx
    #                                     46ad5a  mov     edi, ebx
    #
    #                             ╭▸╭────▸46ad5c  mov     eax, ebx
    #                             │ │
    #               ╭────────────▸│ │     46ad5e  mov     dword ptr [ebp-0x40], eax
    #               │             │ │     46ad61  cmp     edi, 0x4
    # ╭────────────╴│             │ │     46ad64  jae     0x46aee4
    # │             │             │ │
    # │             │             │ │     46ad6a  cmp     eax, 0x2
    # │             │             │ │   ╭╴46ad6d  je      0x46ad83
    # │             │             │ │   │
    # │             │             │ │   │ 46ad6f  push    0x490284
    # │             │             │ │   │ 46ad74  push    edx
    # │             │             │ │   │ 46ad75  call    0x47a27c
    # │             │             │ │   │
    # │             │             │ │   │ 46ad7a  mov     edx, dword ptr [ebp-0x3c]
    # │             │             │ │   │ 46ad7d  pop     ecx
    # │             │             │ │   │ 46ad7e  pop     ecx
    # │             │             │ │   │ 46ad7f  mov     ecx, eax
    # │             │             │ │ ╭╴│ 46ad81  jmp     0x46ad97
    # │             │             │ │ │ │
    # │             │             │ │ │ ╰▸46ad83  mov     ecx, edx
    # │             │             │ │ │   46ad85  lea     esi, [ecx+0x2]
    # │             │             │ │ │
    # │             │             │ │ │ ╭▸46ad88  mov     ax, word ptr [ecx]
    # │             │             │ │ │ │ 46ad8b  add     ecx, 0x2
    # │             │             │ │ │ │ 46ad8e  cmp     ax, bx
    # │             │             │ │ │ ╰╴46ad91  jne     0x46ad88
    # │             │             │ │ │
    # │             │             │ │ │   46ad93  sub     ecx, esi
    # │             │             │ │ │   46ad95  sar     ecx, 0x1
    # │             │             │ │ │
    # │             │             │ │ ╰──▸46ad97  mov     eax, dword ptr [ebp-0x38]
    # │             │             │ │     46ad9a  inc     edi
    # │             │             │ │     46ad9b  mov     esi, dword ptr [ebp-0x38]
    # │             │             │ │     46ad9e  add     dword ptr [ebp-0x38], 0xc
    # │             │             │ │     46ada2  mov     dword ptr [eax-0x4], edx
    # │             │             │ │     46ada5  lea     edx, [edx+ecx*0x2]
    # │             │             │ │     46ada8  mov     dword ptr [eax], ecx
    # │             │             │ │     46adaa  mov     eax, dword ptr [ebp-0x40]
    # │             │             │ │     46adad  mov     dword ptr [esi+0x4], eax
    # │             │             │ │     46adb0  movzx   eax, word ptr [edx]
    # │             │             │ │     46adb3  add     edx, 0x2
    # │             │             │ │     46adb6  mov     esi, dword ptr [ebp-0x44]
    # │             │             │ │     46adb9  mov     dword ptr [ebp-0x3c], edx
    # │             │             │ │     46adbc  sub     eax, 0x2d
    # │             │             │ ╰────╴46adbf  je      0x46ad5c
    # │             │             │
    # │             │             │       46adc1  sub     eax, 0x1
    # │             │             │   ╭──╴46adc4  je      0x46ae2f
    # │             │             │   │
    # │             │             │   │   46adc6  sub     eax, 0x31
    # │             │             ╰──╴│   46adc9  je      0x46ad5c
    # │             │                 │
    # │             │                 │   46adcb  sub     edi, 0x1
    # │   ╭────────╴│                 │   46adce  je      0x46aed6
    # │   │         │                 │
    # │   │         │                 │   46add4  sub     edi, 0x1
    # │   │       ╭╴│                 │   46add7  je      0x46ae90
    # │   │       │ │                 │
    # │   │       │ │                 │   46addd  sub     edi, 0x1
    # │   │       │ │                 │ ╭╴46ade0  je      0x46ae37
    # │   │       │ │                 │ │
    # │   │       │ │                 │ │ 46ade2  sub     edi, 0x1
    # │ ╭╴│       │ │                 │ │ 46ade5  jne     0x46aee4
    # │ │ │       │ │                 │ │
    # │ │ │       │ │                 │ │ 46adeb  lea     eax, [ebp-0x34]
    # │ │ │       │ │                 │ │ 46adee  push    eax
    # │ │ │       │ │                 │ │ 46adef  push    esi
    # │ │ │       │ │                 │ │ 46adf0  call    0x46af34
    # │ │ │       │ │                 │ │
    # │ │ │       │ │                 │ │ 46adf5  pop     ecx
    # │ │ │       │ │                 │ │ 46adf6  pop     ecx
    # │ │ │       │ │                 │ │ 46adf7  test    al, al
    # │ │ │ ╭────╴│ │                 │ │ 46adf9  je      0x46aed2
    # │ │ │ │     │ │                 │ │
    # │ │ │ │     │ │                 │ │ 46adff  lea     eax, [ebp-0x28]
    # │ │ │ │     │ │                 │ │ 46ae02  push    eax
    # │ │ │ │     │ │                 │ │ 46ae03  push    esi
    # │ │ │ │     │ │                 │ │ 46ae04  call    0x46b064
    # │ │ │ │     │ │                 │ │
    # │ │ │ │     │ │                 │ │ 46ae09  pop     ecx
    # │ │ │ │     │ │                 │ │ 46ae0a  pop     ecx
    # │ │ │ │     │ │                 │ │ 46ae0b  test    al, al
    # │ │ │ │ ╭──╴│ │                 │ │ 46ae0d  je      0x46aed2
    # │ │ │ │ │   │ │                 │ │
    # │ │ │ │ │   │ │                 │ │ 46ae13  lea     eax, [ebp-0x1c]
    # │ │ │ │ │   │ │                 │ │ 46ae16  push    eax
    # │ │ │ │ │   │ │                 │ │ 46ae17  push    esi
    # │ │ │ │ │   │ │                 │ │ 46ae18  call    0x46afa6
    # │ │ │ │ │   │ │                 │ │
    # │ │ │ │ │   │ │                 │ │ 46ae1d  pop     ecx
    # │ │ │ │ │   │ │                 │ │ 46ae1e  pop     ecx
    # │ │ │ │ │   │ │                 │ │ 46ae1f  test    al, al
    # │ │ │ │ │ ╭╴│ │                 │ │ 46ae21  je      0x46aed2
    # │ │ │ │ │ │ │ │                 │ │
    # │ │ │ │ │ │ │ │                 │ │ 46ae27  lea     eax, [ebp-0x10]
    # │ │ │ │ │ │ │ │ ╭──────────────╴│ │ 46ae2a  jmp     0x46aec3
    # │ │ │ │ │ │ │ │ │               │ │
    # │ │ │ │ │ │ │ │ │               ╰▸│ 46ae2f  push    0x2
    # │ │ │ │ │ │ │ │ │                 │ 46ae31  pop     eax
    # │ │ │ │ │ │ │ ╰╴│                 │ 46ae32  jmp     0x46ad5e
    # │ │ │ │ │ │ │   │                 │
    # │ │ │ │ │ │ │   │                 ╰▸46ae37  lea     eax, [ebp-0x34]
    # │ │ │ │ │ │ │   │                   46ae3a  push    eax
    # │ │ │ │ │ │ │   │                   46ae3b  push    esi
    # │ │ │ │ │ │ │   │                   46ae3c  call    0x46af34
    # │ │ │ │ │ │ │   │
    # │ │ │ │ │ │ │   │                   46ae41  pop     ecx
    # │ │ │ │ │ │ │   │                   46ae42  pop     ecx
    # │ │ │ │ │ │ │   │                   46ae43  test    al, al
    # │ │ │ │ │ │ │   │ ╭────────────────╴46ae45  je      0x46aed2
    # │ │ │ │ │ │ │   │ │
    # │ │ │ │ │ │ │   │ │                 46ae4b  lea     eax, [ebp-0x28]
    # │ │ │ │ │ │ │   │ │                 46ae4e  push    eax
    # │ │ │ │ │ │ │   │ │                 46ae4f  push    esi
    # │ │ │ │ │ │ │   │ │                 46ae50  call    0x46b064
    # │ │ │ │ │ │ │   │ │
    # │ │ │ │ │ │ │   │ │                 46ae55  pop     ecx
    # │ │ │ │ │ │ │   │ │                 46ae56  pop     ecx
    # │ │ │ │ │ │ │   │ │                 46ae57  test    al, al
    # │ │ │ │ │ │ │   │ │               ╭╴46ae59  je      0x46ae7b
    # │ │ │ │ │ │ │   │ │               │
    # │ │ │ │ │ │ │   │ │               │ 46ae5b  lea     eax, [ebp-0x1c]
    # │ │ │ │ │ │ │   │ │               │ 46ae5e  push    eax
    # │ │ │ │ │ │ │   │ │               │ 46ae5f  push    esi
    # │ │ │ │ │ │ │   │ │               │ 46ae60  call    0x46afa6
    # │ │ │ │ │ │ │   │ │               │
    # │ │ │ │ │ │ │   │ │               │ 46ae65  pop     ecx
    # │ │ │ │ │ │ │   │ │               │ 46ae66  pop     ecx
    # │ │ │ │ │ │ │   │ │               │ 46ae67  test    al, al
    # │ │ │ │ │ │ │   │ │ ╭────────────╴│ 46ae69  jne     0x46aed0
    # │ │ │ │ │ │ │   │ │ │             │
    # │ │ │ │ │ │ │   │ │ │             │ 46ae6b  lea     eax, [ebp-0x1c]
    # │ │ │ │ │ │ │   │ │ │             │ 46ae6e  push    eax
    # │ │ │ │ │ │ │   │ │ │             │ 46ae6f  push    esi
    # │ │ │ │ │ │ │   │ │ │             │ 46ae70  call    0x46aef5
    # │ │ │ │ │ │ │   │ │ │             │
    # │ │ │ │ │ │ │   │ │ │             │ 46ae75  pop     ecx
    # │ │ │ │ │ │ │   │ │ │             │ 46ae76  pop     ecx
    # │ │ │ │ │ │ │   │ │ │             │ 46ae77  test    al, al
    # │ │ │ │ │ │ │   │ │ │ ╭──────────╴│ 46ae79  jne     0x46aed0
    # │ │ │ │ │ │ │   │ │ │ │           │
    # │ │ │ │ │ │ │   │ │ │ │           ╰▸46ae7b  lea     eax, [ebp-0x28]
    # │ │ │ │ │ │ │   │ │ │ │             46ae7e  push    eax
    # │ │ │ │ │ │ │   │ │ │ │             46ae7f  push    esi
    # │ │ │ │ │ │ │   │ │ │ │             46ae80  call    0x46afa6
    # │ │ │ │ │ │ │   │ │ │ │
    # │ │ │ │ │ │ │   │ │ │ │             46ae85  pop     ecx
    # │ │ │ │ │ │ │   │ │ │ │             46ae86  pop     ecx
    # │ │ │ │ │ │ │   │ │ │ │             46ae87  test    al, al
    # │ │ │ │ │ │ │   │ │ │ │ ╭──────────╴46ae89  je      0x46aed2
    # │ │ │ │ │ │ │   │ │ │ │ │
    # │ │ │ │ │ │ │   │ │ │ │ │           46ae8b  lea     eax, [ebp-0x1c]
    # │ │ │ │ │ │ │   │ │ │ │ │   ╭──────╴46ae8e  jmp     0x46aec3
    # │ │ │ │ │ │ │   │ │ │ │ │   │
    # │ │ │ │ │ │ ╰──▸│ │ │ │ │   │       46ae90  lea     eax, [ebp-0x34]
    # │ │ │ │ │ │     │ │ │ │ │   │       46ae93  push    eax
    # │ │ │ │ │ │     │ │ │ │ │   │       46ae94  push    esi
    # │ │ │ │ │ │     │ │ │ │ │   │       46ae95  call    0x46af34
    # │ │ │ │ │ │     │ │ │ │ │   │
    # │ │ │ │ │ │     │ │ │ │ │   │       46ae9a  pop     ecx
    # │ │ │ │ │ │     │ │ │ │ │   │       46ae9b  pop     ecx
    # │ │ │ │ │ │     │ │ │ │ │   │       46ae9c  test    al, al
    # │ │ │ │ │ │     │ │ │ │ │ ╭╴│       46ae9e  je      0x46aed2
    # │ │ │ │ │ │     │ │ │ │ │ │ │
    # │ │ │ │ │ │     │ │ │ │ │ │ │       46aea0  lea     eax, [ebp-0x28]
    # │ │ │ │ │ │     │ │ │ │ │ │ │       46aea3  push    eax
    # │ │ │ │ │ │     │ │ │ │ │ │ │       46aea4  push    esi
    # │ │ │ │ │ │     │ │ │ │ │ │ │       46aea5  call    0x46b064
    # │ │ │ │ │ │     │ │ │ │ │ │ │
    # │ │ │ │ │ │     │ │ │ │ │ │ │       46aeaa  pop     ecx
    # │ │ │ │ │ │     │ │ │ │ │ │ │       46aeab  pop     ecx
    # │ │ │ │ │ │     │ │ │ │ │ │ │       46aeac  test    al, al
    # │ │ │ │ │ │     │ │ │ │ │ │ │ ╭────╴46aeae  jne     0x46aed0
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │     46aeb0  lea     eax, [ebp-0x28]
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │     46aeb3  push    eax
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │     46aeb4  push    esi
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │     46aeb5  call    0x46afa6
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │     46aeba  pop     ecx
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │     46aebb  pop     ecx
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │     46aebc  test    al, al
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │ ╭──╴46aebe  jne     0x46aed0
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │ │
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │ │   46aec0  lea     eax, [ebp-0x28]
    # │ │ │ │ │ │     │ │ │ │ │ │ │ │ │
    # │ │ │ │ │ │     ╰▸│ │ │ │ │ ╰▸│ │   46aec3  push    eax
    # │ │ │ │ │ │       │ │ │ │ │   │ │   46aec4  push    esi
    # │ │ │ │ │ │       │ │ │ │ │   │ │   46aec5  call    0x46aef5
    # │ │ │ │ │ │       │ │ │ │ │   │ │
    # │ │ │ │ │ │       │ │ │ │ │   │ │   46aeca  pop     ecx
    # │ │ │ │ │ │       │ │ │ │ │   │ │   46aecb  pop     ecx
    # │ │ │ │ │ │       │ │ │ │ │   │ │   46aecc  test    al, al
    # │ │ │ │ │ │       │ │ │ │ │   │ │ ╭╴46aece  je      0x46aed2
    # │ │ │ │ │ │       │ │ │ │ │   │ │ │
    # │ │ │ │ │ │       │ ╰▸╰▸│ │   ╰▸╰▸│ 46aed0  mov     bl, 0x1
    # │ │ │ │ │ │       │     │ │       │
    # │ │ │ ╰▸╰▸╰──────▸╰────▸╰▸╰──────▸╰▸46aed2  mov     al, bl
    # │ │ │                           ╭──╴46aed4  jmp     0x46aee6
    # │ │ │                           │
    # │ │ ╰──────────────────────────▸│   46aed6  lea     eax, [ebp-0x34]
    # │ │                             │   46aed9  push    eax
    # │ │                             │   46aeda  push    esi
    # │ │                             │   46aedb  call    0x46af34
    # │ │                             │
    # │ │                             │   46aee0  pop     ecx
    # │ │                             │   46aee1  pop     ecx
    # │ │                             │ ╭╴46aee2  jmp     0x46aee6
    # │ │                             │ │
    # ╰▸╰────────────────────────────▸│ │ 46aee4  xor     al, al
    #                                 │ │
    #                                 ╰▸╰▸46aee6  mov     ecx, dword ptr [ebp-0x4]
    #                                     46aee9  pop     edi
    #                                     46aeea  pop     esi
    #                                     46aeeb  xor     ecx, ebp
    #                                     46aeed  pop     ebx
    #                                     46aeee  call    0x42e0ad
    #
    #                                     46aef3  leave
    #                                     46aef4  ret

    FUNC_BYTES = bytes.fromhex(
        "8bff558bec83ec44a100f1490033c58945fc8b450c53568b750833db5768ca01000053568975bc8945c4e8e256fcff8b55"
        "c48d4dd083c40c894dc88bfb8bc38945c083ff040f837a01000083f8027414688402490052e802f500008b55c459598bc8"
        "eb148bca8d7102668b0183c102663bc375f52bced1f98b45c8478b75c88345c80c8950fc8d144a89088b45c08946040fb7"
        "0283c2028b75bc8955c483e82d749b83e801746983e831749183ef010f840201000083ef010f84b300000083ef01745583"
        "ef010f85f90000008d45cc5056e83f010000595984c00f84d30000008d45d85056e85b020000595984c00f84bf0000008d"
        "45e45056e889010000595984c00f84ab0000008d45f0e9940000006a0258e927ffffff8d45cc5056e8f300000059598"
        "4c00f84870000008d45d85056e80f020000595984c074208d45e45056e841010000595984c075658d45e45056e88000000"
        "0595984c075558d45d85056e821010000595984c074478d45e4eb338d45cc5056e89a000000595984c074328d45d85056e8"
        "ba010000595984c075208d45d85056e8ec000000595984c075108d45d85056e82b000000595984c07402b3018ac3eb108d"
        "45cc5056e8540000005959eb0232c08b4dfc5f5e33cd5be8ba31fcffc9c3"
    )
    BASE = 0x46AD1F

    def test_addr_taken_stack_slot_without_own_def(self):
        proj = angr.load_shellcode(self.FUNC_BYTES, "X86", load_address=self.BASE, start_offset=0)
        cfg = proj.analyses.CFGFast(normalize=True, function_starts=[self.BASE])
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        func = cfg.functions[self.BASE]
        # decompilation raised KeyError before the address-taken-slot definition fix.
        dec = proj.analyses.Decompiler(func, cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None


if __name__ == "__main__":
    unittest.main()
