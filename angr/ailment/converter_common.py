class SkipConversionNotice(Exception):
    pass


class Converter:
    @staticmethod
    def convert(thing):
        raise NotImplementedError()
