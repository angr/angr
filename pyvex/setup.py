from distutils.core import setup, Extension
setup(name="pyvex", version="1.0",
            ext_modules=[
            	    Extension("pyvex", ["pyvex.c", "pyvex_irsb.c"], include_dirs=["/usr/include/valgrind", "../"])
            ])
