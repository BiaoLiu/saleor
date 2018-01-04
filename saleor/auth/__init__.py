from django.conf import settings
from django.contrib.auth import load_backend, get_user_model, user_logged_in
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured
from django.middleware.csrf import rotate_token
from django.utils.crypto import constant_time_compare
from itsdangerous import URLSafeTimedSerializer

from saleor.sso_client.client import Client


def get_user(request):
    """
    Return the user model instance associated with the given request session.
    If no user is retrieved, return an instance of `AnonymousUser`.
    """
    user = None
    raw_access_token = request.COOKIES.get('token')
    if raw_access_token:
        sso_client = Client(settings.SSO_SERVER, settings.SSO_PUBLIC_KEY, settings.SSO_PRIVATE_KEY)
        access_token = URLSafeTimedSerializer(sso_client.private_key).loads(raw_access_token)
        is_success, user = sso_client.get_user(access_token)

    return user or AnonymousUser()
