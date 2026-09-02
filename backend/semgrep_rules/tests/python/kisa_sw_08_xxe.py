from lxml import etree

def unsafe():
    # ruleid: kisa.sw08.python.unsafe-xml-external-entity
    return etree.XMLParser(resolve_entities=True)

def safe():
    # ok: kisa.sw08.python.unsafe-xml-external-entity
    return etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
