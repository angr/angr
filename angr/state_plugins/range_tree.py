import math

import sys


class RangeTree(object):

    def __init__(self):
        self.root = None
        self.cutoff = 4
        self.count = 1
        pass

    def add(self, start, end, obj):

        # l = end - start
        # l2 = math.pow(2, math.ceil(math.log(l, 2)))

        lower = int(math.pow(2, math.floor(math.log(start, 2)))) if start > 0 else 0
        upper = int(math.pow(2, math.ceil(math.log(end, 2)))) - 1
        if end > upper:
            upper = (upper + 1) * 2 - 1

        if self.root is None:

            #print "Lower: " + str(lower)
            #print "Upper: " + str(upper)

            min = self._min_right(lower, upper)
            self.root, _ = self._insert(None, min, upper, start, end, obj)

        else:

            n = self.root
            n_min = n[1][0]
            n_max = n[1][1]

            #print "n_min:" + str(n_min)
            #print "n_max: " + str(n_max)

            if self._extend(start, end, obj, lower, upper):
                #print "skipping..."
                return

            if start > n_max or end < n_min:
                return

            self.root, _ = self._insert(n, n[1][0], n[1][1], start, end, obj)

    def _intersect(self, a_min, a_max, b_min, b_max):

        if a_min >= b_min and a_min <= b_max:
            return True

        if b_min >= a_min and b_min <= a_max:
            return True

        if a_max >= b_min and a_max <= b_max:
            return True

        if b_max >= a_min and b_max <= a_max:
            return True

        return False

    def _insert(self, node, range_min, range_max, start, end, obj, join=None):

        assert join is None or type(join) in (list,)

        to_add_to_parent = set()
        range_len = range_max - range_min + 1

        #print "Inserting in [" + str(range_min) + ", " + str(range_max) + "]"

        #print "Range min: " + str(range_min)
        #print "Range max: " + str(range_max)
        #print "Range len: " + str(range_len)

        has_intersection = self._intersect(range_min, range_max, start, end)
        add_to_this_node = has_intersection and range_len - (min(end, range_max) - max(start, range_min) + 1) < self.cutoff
        add_to_left_child = has_intersection and not add_to_this_node and start < range_min + range_len / 2
        add_to_right_child = has_intersection and not add_to_this_node and end >= range_min + range_len / 2

        #print "Add to: current=" + str(add_to_this_node) + " left=" + str(add_to_left_child) + " right=" + str(add_to_right_child)

        if join is not None:

            if (range_min, range_max) == join[1]:
                assert node is None
                #print "Reusing existing join node"
                node = join
                to_add_to_parent = join[3]
                join = None

            else:
                mid = range_min + (range_len / 2)
                if not add_to_left_child and self._intersect(join[1][0], join[1][1], range_min, mid - 1):
                    add_to_left_child = True
                    #print "add_to_left_child flipped to true since intersect with join"

                if not add_to_right_child and self._intersect(join[1][0], join[1][1], mid, range_max):
                    add_to_left_child = True
                    #print "add_to_right_child flipped to true since intersect with join"

        if node is not None and (add_to_this_node or (add_to_left_child and add_to_right_child)):

            # check if current node is the range that we expect
            if not (range_min, range_max) == node[1]:

                old_node = node
                node = [0, (range_min, range_max), [None, None], set(), self.count]
                #print "[1] Creating node #" + str(self.count) + " as internal expansion"
                self.count += 1

                # add old_node as a child
                if range_min + (range_len / 2) - 1 >= node[1][1]:
                    node[2][0] = old_node
                else:
                    node[2][1] = old_node

                node[3] |= old_node[3]

        if node is None and (add_to_this_node or (add_to_right_child and add_to_left_child)):

            if join is not None and (range_min, range_max) == join[1]:
                #print "Reusing existing join node"
                node = join
                to_add_to_parent = join[3]
                join = None
            else:
                # [number of objs, (min_range, max_range), children, objs]
                node = [0, (range_min, range_max), [None, None], set(), self.count]
                #print "[2] Creating node #" + str(self.count)
                self.count += 1

        if add_to_this_node or (node is not None and (add_to_right_child or add_to_left_child)):
            #print "Appending..."
            node[3].add(obj)

        if add_to_left_child:

            #print "Recursive on left child of [" + str(range_min) + ", " + str(range_max) + "]"

            r = (range_min, range_min + (range_len / 2) - 1)
            left, to_add_from_left = self._insert(node[2][0] if node is not None else None, r[0], r[1], start, end, obj, join)
            if node is None:
                return left, to_add_from_left
            else:
                node[2][0] = left
                to_add_to_parent |= to_add_from_left
                node[3] |= to_add_from_left

        if add_to_right_child:

            #print "Recursive on right child of [" + str(range_min) + ", " + str(range_max) + "]"

            r = (range_min + (range_len / 2), range_max)
            right, to_add_from_right = self._insert(node[2][1] if node is not None else None, r[0], r[1], start, end, obj, join)
            if node is None:
                return right, to_add_from_right
            else:
                node[2][1] = right
                to_add_to_parent |= to_add_from_right
                node[3] |= to_add_from_right

        return node, to_add_to_parent

    def _extend(self, start, end, obj, lower, upper):

        n = self.root
        n_min = n[1][0]
        n_max = n[1][1]

        if lower >= n_min and upper <= n_max:
            return False

        # extend range both right and left
        if lower < n_min and upper > n_max:

            range_min = self._min_right(lower, upper)
            range_max = upper

        elif lower < n_min:

            range_min = self._min_right(lower, n_max)
            range_max = n_max

        else: # upper > n_max

            range_min = self._min_right(n_min, upper)
            range_max = upper

        self.root, _ = self._insert(None, range_min, range_max, start, end, obj, join=n)

        return True

    def _min_right(self, lower, upper):

        min = 0
        range_len = upper + 1

        #print "searching for min in: [" + str(lower) + ", " + str(upper) + "]"
        #print "range_len: " + str(range_len)

        while True:
            if (min + (range_len / 2)) - 1 < lower:
                min += range_len / 2
                #print "min: " + str(min)
                range_len /= 2
            else:
                break

        return min

    def _to_string(self, n):

        if n is None:
            return ""

        s = ""
        if n[2] is not None:
            for c in n[2]:
                if c is not None:
                    s += "\n" + self._to_string(c)

        return "#" + str(n[4]) + ": [" + str(len(n[3])) + ", (" + str(n[1][0]) + ', ' + str(n[1][1]) + '), ' + \
               '[' + ', '.join([(str(c[4]) if c is not None else 'None') for c in n[2]]) + '], ' + \
               ('None' if len(n[3]) == 0 else ' '.join([str(o) for o in n[3]]) ) + "]" + s


    def __repr__(self):
        return self._to_string(self.root)


if __name__ == '__main__':

    t = RangeTree()
    R = [[32, 63], [32, 42], [25, 33], [10, 22]]

    for r in R:
        print("Adding: " +  str(r[0]) + '-' + str(r[1]))
        t.add(r[0], r[1], str(r[0]) + '-' + str(r[1]))
        print(t)
        print()