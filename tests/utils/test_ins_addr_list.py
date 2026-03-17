# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations
from unittest import main, TestCase

from angr.utils.ins_addr_list import InsAddrList


class TestInsAddrList(TestCase):
    def test_ins_addr_list_initialization(self):
        ins_addr_list = InsAddrList(0x400000, ins_sizes=b"\x00")
        assert len(ins_addr_list) == 1
        assert ins_addr_list[0] == 0x400000

        ins_addr_list = InsAddrList(0x400000, ins_sizes=b"\x01\x02\x00")
        assert len(ins_addr_list) == 3
        assert ins_addr_list[0] == 0x400000
        assert ins_addr_list[1] == 0x400001
        assert ins_addr_list[2] == 0x400003

    def test_ins_addr_from_addr_list(self):
        ins_addr_list = InsAddrList.from_addr_list([0x400000, 0x400001, 0x400003])
        assert len(ins_addr_list) == 3
        assert ins_addr_list[0] == 0x400000
        assert ins_addr_list[1] == 0x400001
        assert ins_addr_list[2] == 0x400003

    def test_ins_addr_list_equality(self):
        ins_addr_list1 = InsAddrList(0x400000, ins_sizes=b"\x01\x02\x00")
        ins_addr_list2 = InsAddrList(0x400000, ins_sizes=b"\x01\x02\x00")
        ins_addr_list3 = InsAddrList(0x400000, ins_sizes=b"\x01\x03\x00")

        assert ins_addr_list1 == ins_addr_list2
        assert ins_addr_list1 != ins_addr_list3

    def test_ins_addr_list_add_and_iadd(self):
        ins_addr_list1 = InsAddrList(0x400000, ins_sizes=b"\x01\x02\x00")
        ins_addr_list2 = InsAddrList(0x400003, ins_sizes=b"\x01\x02\x00")

        combined_list = ins_addr_list1 + ins_addr_list2
        assert isinstance(combined_list, list)
        assert len(combined_list) == 6
        assert combined_list[0] == 0x400000
        assert combined_list[1] == 0x400001
        assert combined_list[2] == 0x400003
        assert combined_list[3] == 0x400003
        assert combined_list[4] == 0x400004
        assert combined_list[5] == 0x400006

        ins_addr_list1 += ins_addr_list2
        assert isinstance(ins_addr_list1, list)
        assert len(ins_addr_list1) == 6
        assert ins_addr_list1[0] == 0x400000
        assert ins_addr_list1[1] == 0x400001
        assert ins_addr_list1[2] == 0x400003
        assert ins_addr_list1[3] == 0x400003
        assert ins_addr_list1[4] == 0x400004
        assert ins_addr_list1[5] == 0x400006

    def test_ins_addr_list_add_far_away(self):
        ins_addr_list1 = InsAddrList(0x400000, ins_sizes=b"\x01\x02\x00")
        ins_addr_list2 = InsAddrList(0xA00003, ins_sizes=b"\x01\x02\x00")

        combined_list = ins_addr_list1 + ins_addr_list2
        assert isinstance(combined_list, list)
        assert len(combined_list) == 6
        assert combined_list[0] == 0x400000
        assert combined_list[1] == 0x400001
        assert combined_list[2] == 0x400003
        assert combined_list[3] == 0xA00003
        assert combined_list[4] == 0xA00004
        assert combined_list[5] == 0xA00006


if __name__ == "__main__":
    main()
