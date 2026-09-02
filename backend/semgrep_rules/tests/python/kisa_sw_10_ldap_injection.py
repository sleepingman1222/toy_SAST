def unsafe(request, conn):
    filt = request.GET.get("filter")
    # ruleid: kisa.sw10.python.external-input-to-ldap-filter
    return conn.search_s("dc=example,dc=com", 2, filt)

def safe(conn):
    # ok: kisa.sw10.python.external-input-to-ldap-filter
    return conn.search_s("dc=example,dc=com", 2, "(uid=alice)")
