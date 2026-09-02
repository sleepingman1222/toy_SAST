class kisa_sw_47_public_data_to_private_array:
    def __init__(self, items):
        # ruleid: kisa.sw47.python.external-list-assigned-to-private-field
        self._items = items

class Safe:
    def __init__(self, items):
        # ok: kisa.sw47.python.external-list-assigned-to-private-field
        self._items = list(items)
