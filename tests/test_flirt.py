import os.path

from common import bin_location
import angr


def test_amd64_elf_static_libc_ubuntu_2004():
    binary_path = os.path.join(bin_location, "tests", "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
    proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
    cfg = proj.analyses.CFGFast(show_progressbar=True) #, detect_tail_calls=True)
    flirt_path = os.path.join(bin_location, "tests", "x86_64", "libc_ubuntu_2004.sig")
    proj.analyses.Flirt(flirt_path)

    assert cfg.functions[0x415cc0].name == "_IO_file_open"
    assert cfg.functions[0x415cc0].is_default_name is False
    assert cfg.functions[0x415cc0].from_signature == "flirt"
    assert cfg.functions[0x436980].name == "__mempcpy_chk_avx512_no_vzeroupper"
    assert cfg.functions[0x436980].is_default_name is False
    assert cfg.functions[0x436980].from_signature == "flirt"


if __name__ == "__main__":
    test_amd64_elf_static_libc_ubuntu_2004()
