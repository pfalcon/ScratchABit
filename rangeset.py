# Supports operations only on non-overlapping, adjucent or fully contained ranges
# i.e. unioning (10, 30) and (20, 40) may not work
class RangeSet:

    def __init__(self):
        self.r = []

    @staticmethod
    def _contained(r1, r2):
        return r1[1] <= r2[1]

    def add(self, r):
        last = len(self.r) - 1
        for i, t in enumerate(self.r):
            if r[0] == t[1]:
                new = (t[0], r[1])
                if i != last and new[1] == self.r[i + 1][0]:
                    self.r[i] = (new[0], self.r[i + 1][1])
                    del self.r[i + 1]
                else:
                    self.r[i] = new
                return
            elif r[1] == t[0]:
                new = (r[0], t[1])
                if i != 0 and new[0] == self.r[i - 1][1]:
                    self.r[i] = (self.r[i - 1][0], new[1])
                    del self.r[i - 1]
                else:
                    self.r[i] = new
                return
            elif r[0] < t[0]:
                if i > 0:
                    if self._contained(r, self.r[i - 1]):
                        return
                self.r.insert(i, r)
                return
        if last >= 0 and self._contained(r, self.r[-1]):
            return
        self.r.append(r)

    def bounds(self):
        if self.r:
            return (self.r[0][0], self.r[-1][1])

    def __str__(self):
        return str(self.r)

    def str(self, render=lambda x: str(x)):
        rlist = [(render(x[0]), render(x[1])) for x in self.r]
        return str(rlist)

    # This allows to apply list(), but this creates a copy, using
    # to_list() is more efficient.
    def __iter__(self):
        return iter(self.r)

    def to_list(self):
        return self.r


if __name__ == "__main__":
    r = RangeSet()
    r.add((10, 20))
    assert r.to_list() == [(10, 20)]
    r.add((1, 5))
    assert r.to_list() == [(1, 5), (10, 20)]
    r.add((100, 110))
    assert r.to_list() == [(1, 5), (10, 20), (100, 110)]
    r.add((5, 8))
    assert r.to_list() == [(1, 8), (10, 20), (100, 110)]
    r.add((8, 10))
    assert r.to_list() == [(1, 20), (100, 110)]
    r.add((110, 120))
    assert r.to_list() == [(1, 20), (100, 120)]
    r.add((5, 10))
    assert r.to_list() == [(1, 20), (100, 120)]

    r = RangeSet()
    r.add((10, 20))
    r.add((12, 15))
    assert r.to_list() == [(10, 20)]

    r = RangeSet()
    r.add((10, 30))
    r.add((20, 40))
    #assert r.to_list() == [(10, 40)]
    print(list(r))

    r = RangeSet()
    r.add((30, 40))
    r.add((10, 20))
    r.add((20, 30))
    assert r.to_list() == [(10, 40)]

    r = RangeSet()
    r.add((10, 20))
    r.add((1, 10))
    assert r.to_list() == [(1, 20)]
