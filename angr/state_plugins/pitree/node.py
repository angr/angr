def _max(m):
    # filter all None's out before max'ing
    return max(list(filter(lambda i: i is not None, m)))


class Node(object):
    def __init__(self, interval, mmax, parent):
        self.interval = interval
        self.max = mmax
        self.parent = parent
        self.left_child = None
        self.right_child = None
        self.left_depth = 0
        self.right_depth = 0

    @property
    def balancing_factor(self):
        return self.right_depth - self.left_depth

    def rebalance(self):
        p = self.parent
        if isinstance(p, Root):
            return
        if self == p.left_child:
            p.left_depth  = 1 + max(self.left_depth, self.right_depth)
        else:
            p.right_depth = 1 + max(self.left_depth, self.right_depth)

        if p.balancing_factor <= -2:
            if p.left_child.right_depth <= p.left_child.left_depth:
                p.rotationRight()
            else:
                p.left_child.rotationLeft()
                p.rotationRight()
        elif p.balancing_factor >= 2:
            if p.right_child.left_depth <= p.right_child.right_depth:
                p.rotationLeft()
            else:
                p.right_child.rotationRight()
                p.rotationLeft()
        else:
            p.rebalance()

    def rotationRight(self):
        z = self.left_child
        t = z.right_child
        if self.parent.left_child == self:
            self.parent.left_child = z
        elif self.parent.right_child == self:
            self.parent.right_child = z
        else:
            raise Exception("rotationRight(): something wrong " + str(self.interval))
        z.parent = self.parent
        self.parent = z
        z.right_child = self
        self.left_child = t
        if t is not None:
            t.parent = self
        self.left_depth = z.right_depth
        z.right_depth = 1 + max(self.left_depth, self.right_depth)
        lm = self.left_child.max  if self.left_child  is not None else None
        rm = self.right_child.max if self.right_child is not None else None
        self.max = _max((self.interval.end, lm, rm))
        lm = z.left_child.max  if z.left_child  is not None else None
        rm = z.right_child.max if z.right_child is not None else None
        z.max = _max((z.interval.end, lm, rm))

    def rotationLeft(self):
        z = self.right_child
        t = z.left_child
        if self.parent.left_child == self:
            self.parent.left_child = z
        elif self.parent.right_child == self:
            self.parent.right_child = z
        else:
            raise Exception("rotationLeft(): something wrong 1 " + str(self.interval))
        z.parent = self.parent
        self.parent = z
        z.left_child = self
        self.right_child = t
        if t is not None:
            t.parent = self
        self.right_depth = z.left_depth
        z.left_depth = 1 + max(self.left_depth, self.right_depth)
        lm = self.left_child.max  if self.left_child  is not None else None
        rm = self.right_child.max if self.right_child is not None else None
        self.max = _max((self.interval.end, lm, rm))
        lm = z.left_child.max  if z.left_child  is not None else None
        rm = z.right_child.max if z.right_child is not None else None
        z.max = _max((z.interval.end, lm, rm))

    # complexity is O(min(n, k log(n)) where k is the number of overlapping intervals
    def search(self, interval, ris):
        if interval.overlap(self.interval):
            ris.append(self.interval)
        if self.left_child is not None  and self.left_child.max >= interval.begin:
            self.left_child.search(interval, ris)
        if self.right_child is not None and self.interval.begin <= interval.end and self.right_child.max >= interval.begin:
            self.right_child.search(interval, ris)

    def search_point(self, point, ris):
        if self.interval.containsPoint(point):
            ris.append(self.interval)
        if self.left_child is not None  and self.left_child.max >= point:
            self.left_child.search_point(point, ris)
        if self.right_child is not None and self.interval.begin <= point and self.right_child.max >= point:
            self.right_child.search_point(point, ris)

    # complexity is O(n), only for debug purpose
    def linear_search(self, interval, ris):
        if interval.overlap(self.interval):
            ris.append(self.interval)
        if self.left_child is not None:
            self.left_child.linear_search(interval, ris)
        if self.right_child is not None:
            self.right_child.linear_search(interval, ris)

    def add(self, interval):
        if self.max < interval.end:
            self.max = interval.end
        if interval.begin >= self.interval.begin:
            if self.right_child is None:
                self.right_child = Node(interval, interval.end, self)
                self.right_child.rebalance()
            else:
                self.right_child.add(interval)
        else:
            if self.left_child is None:
                self.left_child = Node(interval, interval.end, self)
                self.left_child.rebalance()
            else:
                self.left_child.add(interval)

class Root(object):
    def __init__(self):
        self.left_child = None
        self.right_child = None # Only left_child used
                                # In this way the rotations
                                # are compatible with root change
        self.interval = "ROOT"

    @property
    def child(self):
        return self.left_child

    @child.setter
    def child(self, value):
        self.left_child = value
