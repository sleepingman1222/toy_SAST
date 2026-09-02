import pickle
def unsafe(request):
    data = request.POST.get("data")
    # ruleid: kisa.sw43.python.external-input-to-deserializer
    return pickle.loads(data)
def safe(request):
    import json
    data = request.POST.get("data")
    # ok: kisa.sw43.python.external-input-to-deserializer
    return json.loads(data)
