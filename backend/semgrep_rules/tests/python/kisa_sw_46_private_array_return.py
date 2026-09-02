class kisa_sw_46_private_array_return:
    def __init__(self):
        self._items = []

    def unsafe(self):
        # ruleid: kisa.sw46.python.private-list-return-review
        return self._items

    def safe(self):
        # ok: kisa.sw46.python.private-list-return-review
        return list(self._items)
