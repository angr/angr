from distutils.core import setup, Extension

import os
vgprefix = os.environ["HOME"] + "/valgrind/inst"

setup(name="pyvex", version="1.0",
            ext_modules=[
            	    Extension(
            	    	    "pyvex",
            	    	   ["pyvex.c", "pyvex_irsb.c", "pyvex_irstmt.c"],
            	    	   #["pyvex.c"],
            	    	    include_dirs=[vgprefix + "/include/valgrind", "../"],
            	    	    library_dirs=[vgprefix + "/lib/valgrind"],
            	    	    libraries=["vex-amd64-linux"],
			    extra_objects=["../vex/angr_vex.a"], #, vgprefix + "/lib/valgrind/libvex-amd64-linux.a"],
			    extra_compile_args=["--std=c99"],
            	    )
            ])
