# -*- coding: utf-8 -*-
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.core.handlers.wsgi import WSGIRequest
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.middleware.csrf import rotate_token
from django.views.generic import View
from itsdangerous import URLSafeTimedSerializer
from webservices.sync import SyncConsumer
from urllib.parse import urlparse, urlunparse, urljoin, urlencode

from saleor.utils.response import res_code


class LoginView(View):
    client = None

    def get(self, request):
        scheme = 'https' if request.is_secure() else 'http'
        netloc = request.get_host()
        path = reverse('sso-authenticate')
        next = urlparse(request.META.get('HTTP_REFERER', '/'))
        next = urlunparse(('', '', next[2], next[3], next[4], next[5]))
        query = urlencode([('next', next)])
        # 设定sso登录成功后回调地址 http://127.0.0.1:8015/auth/authenticate/?next=/
        redirect_to = urlunparse((scheme, netloc, path, '', query, ''))
        request_token = self.client.get_request_token(redirect_to)
        host = urljoin(self.client.server_url, 'authorize/')
        url = '%s?%s' % (host, urlencode([('token', request_token)]))
        return HttpResponseRedirect(url)

    def get_next(self):
        """
        Given a request, returns the URL where a user should be redirected to
        after login. Defaults to '/'
        """
        next = self.request.GET.get('next', None)
        if not next:
            return '/'
        netloc = urlparse(next)[1]
        # Heavier security check -- don't allow redirection to a different
        # host.
        # Taken from django.contrib.auth.views.login
        if netloc and netloc != self.request.get_host():
            return '/'
        return next


class AuthenticateView(LoginView):
    def get(self, request):
        raw_access_token = request.GET['access_token']
        payload = URLSafeTimedSerializer(self.client.private_key).loads(raw_access_token)
        payload.get('sid')
        is_success, user = self.client.get_user(payload)
        if hasattr(request, 'user'):
            request.user = user

        next = self.get_next()
        response = HttpResponseRedirect(next)
        response.set_cookie('token', raw_access_token)
        rotate_token(request)
        return response


class RegisterView(View):
    def get_redirect_back(self):
        redirect_back = self.request.META.get('HTTP_REFERER', '')
        if not redirect_back:
            scheme = 'https' if self.request.is_secure() else 'http'
            netloc = self.request.get_host()
            redirect_back = urlunparse((scheme, netloc, '/', '', '', ''))
        return redirect_back

    def get(self, request):
        redirect_back = self.get_redirect_back()
        host = settings.SSO_REGISTER
        url = '%s?%s' % (host, urlencode([('next', redirect_back)]))
        return HttpResponseRedirect(url)


class LogoutView(RegisterView):
    def get(self, request):
        redirect_back = self.get_redirect_back()
        host = settings.SSO_LOGOUT
        url = '%s?%s' % (host, urlencode([('next', redirect_back)]))
        return HttpResponseRedirect(url)


class Client(object):
    login_view = LoginView
    authenticate_view = AuthenticateView
    backend = "%s.%s" % (ModelBackend.__module__, ModelBackend.__name__)
    user_extra_data = None

    def __init__(self, server_url, public_key, private_key,
                 user_extra_data=None):
        self.server_url = server_url
        self.public_key = public_key
        self.private_key = private_key
        self.consumer = SyncConsumer(self.server_url, self.public_key, self.private_key)
        if user_extra_data:
            self.user_extra_data = user_extra_data

    @classmethod
    def from_dsn(cls, dsn):
        parse_result = urlparse(dsn)
        public_key = parse_result.username
        private_key = parse_result.password
        netloc = parse_result.hostname
        if parse_result.port:
            netloc += ':%s' % parse_result.port
        server_url = urlunparse((
            parse_result.scheme, netloc, parse_result.path, parse_result.params, parse_result.query,
            parse_result.fragment))
        return cls(server_url, public_key, private_key)

    def get_request_token(self, redirect_to):
        return self.consumer.consume('/' + settings.SSO_SERVER + 'request-token/', {'redirect_to': redirect_to})[
            'request_token']

    def get_user(self, access_token):
        data = {'access_token': access_token}
        if self.user_extra_data:
            data['extra_data'] = self.user_extra_data
        result = self.consumer.consume('/verify/', data)
        # user = self.build_user(user_data)

        user = None
        is_success = result.get('rescode') == res_code['success']
        if is_success:
            user_data = result.get('data')
            user = User()
            user.id = user_data.get('userid')
            user.username = user_data.get('username')
            user.email = user_data.get('email')
            user.first_name = user_data.get('first_name')
            user.last_name = user_data.get('last_name')
            user.is_staff = user_data.get('is_staff')
            user.is_superuser = user_data.get('is_superuser')
            user.is_active = user_data.get('is_active')
        return is_success, user

    def build_user(self, user_data):
        try:
            user = User.objects.get(username=user_data['username'])
        except User.DoesNotExist:
            user = User(**user_data)
        user.set_unusable_password()
        user.save()
        return user

    def logout(self, access_token):
        data = {'access_token': access_token}
        if self.user_extra_data:
            data['extra_data'] = self.user_extra_data
        user_data = self.consumer.consume('/logout/', data)
        is_success = user_data.get('rescode') == res_code['success']
        return is_success

    # def get_urls(self):
    #     return [
    #         url(r'^$', self.login_view.as_view(client=self), name='simple-sso-login'),
    #         url(r'^authenticate/$', self.authenticate_view.as_view(client=self), name='simple-sso-authenticate'),
    #     ]
