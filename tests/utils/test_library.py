from __future__ import annotations

import unittest

from angr.utils.library import get_cpp_function_name


class TestLibrary(unittest.TestCase):
    """
    Test functions in angr.utils.library.
    """

    # pylint: disable=no-self-use

    def test_get_cpp_function_name(self):
        input_and_expected = [
            ("", ""),
            ("func", "func"),
            ("func(char*, int)", "func"),
            ("int __cdecl Fxi(int (__cdecl *)(int))", "Fxi"),
            ("public: __cdecl S::S(struct S &&)", "S::S"),
            ("printTwice<int>(int x)", "printTwice<int>"),
            ("virtual __cdecl exception::~exception(void)", "exception::~exception"),
            ("public: virtual __cdecl exception::~exception(void)", "exception::~exception"),
            ("public: virtual char const * __cdecl exception::what(void) const", "exception::what"),
            (
                "private: static long __cdecl wil::details_abi::ProcessLocalStorageData<"
                "struct wil::details_abi::ProcessLocalData"
                ">::MakeAndInitialize("
                "unsigned short const *, "
                "class wil::unique_any_t<"
                "class wil::mutex_t<"
                "class wil::details::unique_storage<"
                "struct wil::details::resource_policy<"
                "void *, "
                "void (__cdecl *)(void*) noexcept, "  # cxxheaderparser has trouble supporting void (__cdecl *)
                "&void __cdecl wil::details::CloseHandle(void *), "
                "struct wistd::integral_constant<unsigned __int64, 0>, "
                "void *, "
                "void *, "
                "0, "
                "std::nullptr_t"
                ">"
                ">, "
                "struct wil::err_returncode_policy"
                ">"
                "> "
                "&&,"
                "class wil::details_abi::ProcessLocalStorageData<struct wil::details_abi::ProcessLocalData> **)",
                "wil::details_abi::ProcessLocalStorageData<"
                "struct wil::details_abi::ProcessLocalData"
                ">::MakeAndInitialize",
            ),
            (
                "void __cdecl UptimeTicksToFileTimeBasedULongLong(unsigned __int64, unsigned __int64 *)",
                "UptimeTicksToFileTimeBasedULongLong",
            ),
        ]

        for input_, expected in input_and_expected:
            with self.subTest(input_=input_):
                assert get_cpp_function_name(input_) == expected


if __name__ == "__main__":
    unittest.main()
