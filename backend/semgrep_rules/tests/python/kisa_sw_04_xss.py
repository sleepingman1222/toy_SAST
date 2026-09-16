import html

from django.http import HttpResponse
from django.utils.html import escape
from django.utils.safestring import mark_safe
from markupsafe import Markup


def unsafe_http_response(request):
    value = request.GET.get("q")

    # ruleid: kisa.sw04.python.external-input-to-html-response
    return HttpResponse(value)


def unsafe_concat(request):
    name = request.POST.get("name")

    body = (
        "<h1>Hello "
        + name
        + "</h1>"
    )

    # ruleid: kisa.sw04.python.external-input-to-html-response
    return HttpResponse(body)


def unsafe_mark_safe(request):
    value = request.GET.get("html")

    # ruleid: kisa.sw04.python.external-input-to-html-response
    return mark_safe(value)


def unsafe_markup(request):
    value = request.args.get("html")

    # ruleid: kisa.sw04.python.external-input-to-html-response
    return Markup(value)


def unsafe_multi_step(request):
    value = request.form.get("value")

    first = value
    second = first

    # ruleid: kisa.sw04.python.external-input-to-html-response
    return HttpResponse(second)


def safe_django_escape(request):
    value = request.GET.get("q")

    safe = escape(value)

    # ok: kisa.sw04.python.external-input-to-html-response
    return HttpResponse(safe)


def safe_html_escape(request):
    value = request.GET.get("q")

    safe = html.escape(value)

    # ok: kisa.sw04.python.external-input-to-html-response
    return HttpResponse(safe)


def safe_hardcoded():
    # ok: kisa.sw04.python.external-input-to-html-response
    return HttpResponse("<h1>Hello</h1>")


def safe_template_render(request, render):
    value = request.GET.get("q")

    # ok: kisa.sw04.python.external-input-to-html-response
    return render(
        request,
        "search.html",
        {
            "value": value,
        },
    )
