import angr


def broken_concretize_read_addr1():
    shellcode = b"\x41\x0F\xB7\x04\x56\x41\x8B\x0C\x87\x85\xC9\x0F\x84\x00\x00\x00\x00"
    # movzx  eax,WORD PTR [r14+rdx*2]
    # mov    ecx,DWORD PTR [r15+rax*4]
    # test   ecx,ecx
    # je

    proj = angr.project.load_shellcode(shellcode, arch="amd64")

    arbitrary_number = 10
    two_succs_count = 0

    for i in range(arbitrary_number):
        state = proj.factory.blank_state()
        succs = state.step()

        if len(succs.successors) == 2:
            two_succs_count = two_succs_count + 1

    assert two_succs_count == arbitrary_number


def broken_concretize_read_addr2():
    shellcode = b"\x49\x63\x4B\x3C\x4C\x01\xD9\x0F\x84\x00\x00\x00\x00"
    # movsxd rcx,DWORD PTR [r11+0x3c]
    # add    rcx,r11
    # test   ecx,ecx
    # je

    proj = angr.project.load_shellcode(shellcode, arch="amd64")

    arbitrary_number = 10
    two_succs_count = 0

    for i in range(arbitrary_number):
        state = proj.factory.blank_state()
        succs = state.step()

        if len(succs.successors) == 2:
            two_succs_count = two_succs_count + 1

    assert two_succs_count == arbitrary_number


if __name__ == "__main__":
    broken_concretize_read_addr1()
    broken_concretize_read_addr2()
