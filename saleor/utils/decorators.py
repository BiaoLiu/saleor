from functools import wraps

from django.conf import settings
from django.http import HttpResponseRedirect
from itsdangerous import URLSafeTimedSerializer

from saleor.sso_client.client import Client

sso_client = Client(settings.SSO_SERVER, settings.SSO_PUBLIC_KEY, settings.SSO_PRIVATE_KEY)


def login_required(func):
    '''登录授权验证'''

    @wraps(func)
    def decorator(request, *args, **kwargs):
        raw_access_token = request.COOKIES.get('token')
        if not raw_access_token:
            return HttpResponseRedirect('/client/')
        access_token = URLSafeTimedSerializer(sso_client.private_key).loads(raw_access_token)
        is_success,user = sso_client.get_user(access_token)
        if not is_success:
            return HttpResponseRedirect('/client/')
        if hasattr(request, 'user'):
            request.user = user
        return func(request, *args, **kwargs)
    return decorator
