def unsafe(request, doc):
    query = request.GET.get("xpath")
    # ruleid: kisa.sw09.python.external-input-to-xpath
    return doc.xpath(query)

def safe(doc):
    # ok: kisa.sw09.python.external-input-to-xpath
    return doc.xpath("/users/user")
