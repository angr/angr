from __future__ import annotations


class SkipConversionNotice(Exception):
    pass


class Converter:
    @staticmethod
    def convert(irsb, manager):
        raise NotImplementedError
