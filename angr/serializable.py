from __future__ import annotations


class Serializable:
    """
    The base class of all protobuf-serializable classes in angr.
    """

    __slots__ = ()

    @classmethod
    def _get_cmsg(cls):
        """
        Get a cmessage object.

        :return:    The correct cmessage object.
        """

        raise NotImplementedError

    def serialize_to_cmessage(self):
        """
        Serialize the class object and returns a protobuf cmessage object.

        :return:    A protobuf cmessage object.
        :rtype:     protobuf.cmessage
        """

        raise NotImplementedError

    def serialize(self):
        """
        Serialize the class object and returns a bytes object.

        :return:    A bytes object.
        :rtype:     bytes
        """

        return self.serialize_to_cmessage().SerializeToString()

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        """
        Parse a protobuf cmessage and create a class object.

        :param cmsg:    The probobuf cmessage object.
        :return:        A unserialized class object.
        :rtype:         cls
        """

        raise NotImplementedError

    @classmethod
    def parse(cls, s, **kwargs):
        """
        Parse a bytes object and create a class object.

        :param bytes s: A bytes object.
        :return:        A class object.
        :rtype:         cls
        """

        pb2_obj = cls._get_cmsg()
        pb2_obj.ParseFromString(s)

        return cls.parse_from_cmessage(pb2_obj, **kwargs)
