# teams_chat/settings.py

import os
from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY', default='django-insecure-dev-key-change-in-production')
DEBUG = config('DEBUG', default=True, cast=bool)
ALLOWED_HOSTS = ['*']
if DEBUG and '*' not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append('*')
FERNET_KEY = "Cl6ELr31JUC0z8zmfjTXOKS9dmYKQTx7esJ5Zv065MM="

# -------------------------------
# Installed Apps
# -------------------------------
INSTALLED_APPS = [
    'daphne',  # must be first for Channels/WebSockets

    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party
    'rest_framework',
    'corsheaders',
    'channels',

    # Local apps
    'chat',
    'sslserver',
]

# -------------------------------
# Middleware
# -------------------------------
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',

    'django.middleware.security.SecurityMiddleware',

    # WHITENOISE MUST BE HERE (for static files)
    'whitenoise.middleware.WhiteNoiseMiddleware',

    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# -------------------------------
# URLs & Templates
# -------------------------------
ROOT_URLCONF = 'teams_chat.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],  # project-level templates
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'teams_chat.wsgi.application'
ASGI_APPLICATION = 'teams_chat.asgi.application'

# -------------------------------
# Database (SQLite)
# -------------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# -------------------------------
# Password Validation
# -------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# -------------------------------
# Static and Media Files
# -------------------------------
STATIC_URL = '/static/'

# 🔥 THE FIX YOU MISSED — This loads /static/js/* and /static/css/*
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

STATIC_ROOT = BASE_DIR / 'staticfiles'

# Whitenoise for serving static files
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# -------------------------------
# Upload Limits
# -------------------------------
MAX_UPLOAD_SIZE = 52428800  # 50MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800
DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# -------------------------------
# Django REST Framework
# -------------------------------
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'chat_index'
LOGOUT_REDIRECT_URL = 'login'

# -------------------------------
# CORS
# -------------------------------
CORS_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    'http://10.214.214.51:8000',
]

# -------------------------------
# Channels / WebSockets
# -------------------------------
if DEBUG:
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels.layers.InMemoryChannelLayer',
        }
    }
else:
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels_redis.core.RedisChannelLayer',
            'CONFIG': {
                'hosts': [('127.0.0.1', 6379)],
                'capacity': 1500,
                'expiry': 10,
            },
        },
    }

# -------------------------------
# Logging
# -------------------------------
# Determine the appropriate file handler based on OS
# Windows has issues with RotatingFileHandler during runserver due to file locking [WinError 32]
if os.name == 'nt':
    LOGGING_FILE_HANDLER = {
        'class': 'logging.FileHandler',
        'filename': BASE_DIR / 'logs' / 'django.log',
        'formatter': 'verbose',
    }
else:
    LOGGING_FILE_HANDLER = {
        'class': 'logging.handlers.RotatingFileHandler',
        'filename': BASE_DIR / 'logs' / 'django.log',
        'maxBytes': 1024 * 1024 * 10,
        'backupCount': 10,
        'formatter': 'verbose',
    }

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'file': LOGGING_FILE_HANDLER,
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
}

os.makedirs(BASE_DIR / 'logs', exist_ok=True)
