from django.conf import settings
from django.conf.urls import url

from saleor.sso_client.client import Client

sso_client = Client(settings.SSO_SERVER, settings.SSO_PUBLIC_KEY, settings.SSO_PRIVATE_KEY)

urlpatterns = [
    url(r'^$', sso_client.login_view.as_view(client=sso_client), name='sso-login'),
    url(r'^authenticate/$', sso_client.authenticate_view.as_view(client=sso_client), name='sso-authenticate'),
    url(r'^register/$', sso_client.register_view.as_view(client=sso_client), name='sso-register'),
    url(r'^logout/$', sso_client.logout_view.as_view(client=sso_client), name='sso-logout')
]
