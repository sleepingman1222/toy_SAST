def unsafe(request, Project):
    # ruleid: kisa.sw19.python.external-id-object-access-review
    return Project.objects.get(id=request.GET.get("id"))

def safe(request, Project):
    # ok: kisa.sw19.python.external-id-object-access-review
    return Project.objects.get(id=request.GET.get("id"), owner=request.user)
