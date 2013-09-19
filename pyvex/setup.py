from distutils.core import setup, Extension

import os
vgprefix = os.environ["HOME"] + "/valgrind/inst"

setup(name="pyvex", version="1.0", ext_modules=[Extension(
		"pyvex",
		["pyvex/pyvex.c", "pyvex/pyvex_irsb.c", "pyvex/pyvex_irstmt.c", "pyvex/pyvex_irtypeenv.c", "pyvex/pyvex_irexpr.c", "pyvex/pyvex_enums.c", "pyvex/pyvex_irconst.c", "pyvex/pyvex_ircallee.c", "pyvex/pyvex_irregarray.c", "pyvex/pyvex_logging.c", "pyvex/pyvex_vexir.c"],
		include_dirs=[vgprefix + "/include/valgrind"],
		library_dirs=[vgprefix + "/lib/valgrind"],
		libraries=["vex-amd64-linux"],
		extra_objects=[], #, vgprefix + "/lib/valgrind/libvex-amd64-linux.a"],
		extra_compile_args=["--std=c99"])
	])
