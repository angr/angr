#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

from angr.utils.library import convert_cproto_to_py


class TestSimTypeFunction(unittest.TestCase):
    def test_c_repr(self):
        proto = "int (main)(int argc, char **argv)"
        _, pyproto, _ = convert_cproto_to_py(proto + ";")
        assert pyproto.c_repr(name="main", full=True) == proto

    def test_c_repr_noargs(self):
        _, pyproto, _ = convert_cproto_to_py("int (main)();")
        assert pyproto.c_repr(name="main") == "int (main)(void)"

    def test_c_repr_noname(self):
        _, pyproto, _ = convert_cproto_to_py("int (main)(int argc, char **argv);")
        assert pyproto.c_repr(full=True) == "int ()(int argc, char **argv)"

    def test_c_repr_notfull(self):
        _, pyproto, _ = convert_cproto_to_py("int (main)(int argc, char **argv);")
        assert pyproto.c_repr(name="main", full=False) == "int (main)(int, char **)"

    def test_c_repr_void(self):
        proto = "void (main)(int argc, char **argv)"
        _, pyproto, _ = convert_cproto_to_py(proto + ";")
        assert pyproto.c_repr(name="main", full=True) == proto

    def test_c_repr_variadic(self):
        proto = "int (main)(int x, ...)"
        _, pyproto, _ = convert_cproto_to_py(proto + ";")
        assert pyproto.c_repr(name="main", full=True) == proto

    def test_c_repr_variadic_only(self):
        _, pyproto, _ = convert_cproto_to_py("int (main)(void);")  # XXX: pycparser does not support full variadic yet
        pyproto.variadic = True
        assert pyproto.c_repr(name="main", full=True) == "int (main)(...)"

    def test_c_repr_strtok_qual(self):
        _, pyproto, _ = convert_cproto_to_py(
            "char * (strtok)(char *restrict NEWSTRING, const char *restrict DELIMITERS);"
        )
        assert pyproto.c_repr(name="strtok", full=False) == "char *(strtok)(char *restrict, const char *restrict)"
        assert (
            pyproto.c_repr(name="strtok", full=True)
            == "char *(strtok)(char *restrict NEWSTRING, const char *restrict DELIMITERS)"
        )

    def test_c_repr_strdup_qual(self):
        _, pyproto, _ = convert_cproto_to_py("char * (strdup)(const char *S);")
        assert pyproto.c_repr(name="strdup", full=False) == "char *(strdup)(const char *)"

    def test_c_repr_psignal_qual(self):
        _, pyproto, _ = convert_cproto_to_py("void (psignal) (int SIGNUM, const char *MESSAGE);")
        assert pyproto.c_repr(name="psignal", full=False) == "void (psignal)(int, const char *)"
        assert pyproto.c_repr(name="psignal", full=True) == "void (psignal)(int SIGNUM, const char *MESSAGE)"


if __name__ == "__main__":
    unittest.main()
