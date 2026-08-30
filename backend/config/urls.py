from django.contrib import admin
from django.urls import include, path


urlpatterns = [

    # ========================================
    # Django Admin
    # ========================================

    path(
        "admin/",
        admin.site.urls,
    ),


    # ========================================
    # Accounts API
    # ========================================

    path(
        "api/",
        include("accounts.urls"),
    ),


    # ========================================
    # Projects API
    # ========================================

    path(
        "api/",
        include("projects.urls"),
    ),


    # ========================================
    # Analysis / Scan API
    # ========================================

    path(
        "api/",
        include("scans.urls"),
    ),
]