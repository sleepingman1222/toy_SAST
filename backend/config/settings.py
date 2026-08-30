import os
from pathlib import Path
from datetime import timedelta


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "unsafe-development-secret"
)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get(
    "DJANGO_DEBUG",
    "False"
).lower() == "true"


ALLOWED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "backend",
]


# ========================================
# Application definition
# ========================================

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third Party
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",

    # Local Apps
    "accounts",
    "projects",
    "scans",
]


MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]


ROOT_URLCONF = "config.urls"


TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",

        "DIRS": [],

        "APP_DIRS": True,

        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]


WSGI_APPLICATION = "config.wsgi.application"


# ========================================
# Database
# ========================================

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",

        "NAME": os.environ.get(
            "POSTGRES_DB"
        ),

        "USER": os.environ.get(
            "POSTGRES_USER"
        ),

        "PASSWORD": os.environ.get(
            "POSTGRES_PASSWORD"
        ),

        "HOST": os.environ.get(
            "DB_HOST",
            "postgres"
        ),

        "PORT": os.environ.get(
            "DB_PORT",
            "5432"
        ),
    }
}


# ========================================
# Password validation
# ========================================

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME":
            "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },

    {
        "NAME":
            "django.contrib.auth.password_validation.MinimumLengthValidator",
    },

    {
        "NAME":
            "django.contrib.auth.password_validation.CommonPasswordValidator",
    },

    {
        "NAME":
            "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# ========================================
# Internationalization
# ========================================

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# ========================================
# Static files
# ========================================

STATIC_URL = "static/"


# ========================================
# Media files
#
# SourceVersion의 업로드 파일을
# 저장하기 위해 사용
# ========================================

MEDIA_URL = "/media/"

MEDIA_ROOT = BASE_DIR / "media"


# ========================================
# Default primary key field type
# ========================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ========================================
# Celery
# ========================================

CELERY_BROKER_URL = os.environ.get(
    "REDIS_URL",
    "redis://redis:6379/0"
)


CELERY_RESULT_BACKEND = os.environ.get(
    "REDIS_URL",
    "redis://redis:6379/0"
)


# ========================================
# Django REST Framework
# ========================================

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),

    "DEFAULT_THROTTLE_RATES": {
        "login_ip": "20/minute",
        "login_username": "10/minute",
        "login_ip_username": "5/minute",
    },
}


# ========================================
# JWT
#
# ACCESS_TOKEN 수명
#
# ROTATE_REFRESH_TOKENS:
# refresh 사용할 때 새 refresh 발급
#
# BLACKLIST_AFTER_ROTATION:
# 기존 refresh 폐기
# ========================================

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME":
        timedelta(
            minutes=15
        ),

    "REFRESH_TOKEN_LIFETIME":
        timedelta(
            days=7
        ),

    "ROTATE_REFRESH_TOKENS":
        True,

    "BLACKLIST_AFTER_ROTATION":
        True,
}


# ========================================
# CSRF
# ========================================

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:5173",
]


CSRF_COOKIE_HTTPONLY = False


# ========================================
# Refresh Cookie
# ========================================

REFRESH_COOKIE_SECURE = False

REFRESH_COOKIE_SAMESITE = "Lax"