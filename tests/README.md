These are the non regression tests for Angr.

Place your .c files into src/ and run Make. These will be compiled for all
Angr's supported targets and placed into build/{arch}/test_name.

If you only have a binary, or if for some reason you don't want your tests to
be recompiled, you can place the binaries in the blob folder instead.

By naming your python tests test_blah, nosetest will be able to find them.
https://nose.readthedocs.org/en/latest/
