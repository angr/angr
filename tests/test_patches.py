import os

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_patch_vulnerable_fauxware_amd64():
    binpath = os.path.join(test_location, "x86_64", "vulns", "vulnerable_fauxware")
    proj = angr.Project(binpath, auto_load_libs=False)

    proj.kb.patches.add_patch(0x40094C, b"\x0a")
    patched = proj.kb.patches.apply_patches_to_binary()

    # manual patch
    with open(binpath, "rb") as f:
        binary_data = f.read()
    binary_data = binary_data[:0x94C] + b"\x0a" + binary_data[0x94D:]

    assert patched == binary_data


if __name__ == "__main__":
    test_patch_vulnerable_fauxware_amd64()
