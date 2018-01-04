from functools import wraps

from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse
from itsdangerous import URLSafeTimedSerializer

from saleor.sso_client.client import Client

sso_client = Client(settings.SSO_SERVER, settings.SSO_PUBLIC_KEY, settings.SSO_PRIVATE_KEY)


def login_required(func):
    '''登录授权验证'''

    @wraps(func)
    def decorator(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseRedirect(reverse('sso-login'))
        return func(request, *args, **kwargs)
    return decorator
