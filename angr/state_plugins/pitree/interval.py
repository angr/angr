class Interval(object):
    def __init__(self, begin, end, data=None):
        assert begin <= end
        self.begin  = begin
        self.end = end
        self.data = data

    def containsPoint(self, point):
        return self.begin < point and self.end >= point

    def overlap(self, other):
        return not (self.begin >= other.end or self.end <= other.begin)

    def contains(self, other):
        return self.begin <= other.begin and self.end >= other.end

    def copy(self):
        return Interval(self.begin, self.end, self.data)

    def __eq__(self, other):
        return self.begin == other.begin and self.end == other.end and self.data == other.data

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.begin, self.end))

    def __str__(self):
        return "[" + str(self.begin) + ", " + str(self.end) + "] " + str(self.data)
