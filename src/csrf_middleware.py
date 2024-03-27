from __future__ import annotations

import http
import http.cookies
import re
import typing as t
import uuid
from collections.abc import Sequence

from asgiref.typing import (
    ASGI3Application,
    ASGIReceiveCallable,
    ASGISendCallable,
    ASGISendEvent,
    HTTPScope,
)
from starlette.datastructures import URL, MutableHeaders
from starlette.requests import Request
from starlette.responses import Response

SAFE_HTTP_METHODS = ("GET", "HEAD", "OPTIONS", "TRACE")
ONE_YEAR = 31536000  # 365 * 24 * 60 * 60
DEFAULT_COOKIE_NAME = "csrftoken"
DEFAULT_HEADER_NAME = "X-CSRFToken"


class CSRFMiddleware:
    """
    For GET requests, set a random token as a cookie. For unsafe HTTP methods,
    require a HTTP header to match the cookie value, otherwise the request
    is rejected.

    This uses the Double Submit Cookie style of CSRF prevention. For more
    information see the OWASP cheatsheet (`double submit cookie <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie>`_
    and `customer request headers <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#use-of-custom-request-headers>`_).

    By default, the CSRF token needs to be added to the request header. By
    setting ``allow_form_param`` to ``True``, it will also work if added as a
    form parameter.

    """  # noqa: E501

    @staticmethod
    def get_new_token() -> str:
        return str(uuid.uuid4())

    def __init__(
        self,
        app: ASGI3Application,
        allowed_hosts: list[str] | tuple[str] = (),  # prefer tuple
        cookie_name: str = DEFAULT_COOKIE_NAME,
        header_name: str = DEFAULT_HEADER_NAME,
        max_age: int = ONE_YEAR,
        allow_header_param: bool = True,
        allow_form_param: bool = False,
        exempt_urls_for_get: list[str] | tuple[str] = (),  # prefer tuple
        ** kwargs,
    ):
        """
        :param app:
            The ASGI app you want to wrap.
        :param allowed_hosts:
            If using this middleware with HTTPS, you need to set this value,
            for example ``['example.com']``.
        :param cookie_name:
            You can specify a custom name for the cookie. There should be no
            need to change it, unless in the rare situation where the name
            clashes with another cookie.
        :param header_name:
            You can tell the middleware to look for the CSRF token in a
            different HTTP header.
        :param max_age:
            The max age of the cookie, in seconds.
        :param allow_header_param:
            Whether to look for the CSRF token in the HTTP headers.
        :param allow_form_param:
            Whether to look for the CSRF token in a form field with the same
            name as the cookie. By default, it's not enabled.
        :param exempt_urls_for_get:
            The URLs that won't trigger the set-cookie for the csrftoken can
            be particularly useful for handling the GET requests within the
            formview, especially for sessions making their first request
            to the host.

        """
        if not isinstance(allowed_hosts, (list, tuple)):
            raise ValueError(
                "allowed_hosts must be a list or tuple"
            )
        if not isinstance(exempt_urls_for_get, (list, tuple)):
            raise ValueError(
                "exempt_urls_for_get must be a list or tuple"
            )

        self.app = app
        self.allowed_hosts = allowed_hosts
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.max_age = max_age
        self.allow_header_param = allow_header_param
        self.allow_form_param = allow_form_param
        self.exempt_urls_for_get = exempt_urls_for_get

    def is_valid_referer(self, request: Request) -> bool:
        header: str = (
            request.headers.get("origin")
            or request.headers.get("referer")
            or ""
        )
        url = URL(header)
        hostname = url.hostname
        return hostname in self.allowed_hosts if hostname else False

    def _get_error_response(self, content: str, status_code: http.HTTPStatus) -> Response:
        return Response(content=content, status_code=status_code)

    async def _extract_message(self, receive: ASGIReceiveCallable) -> ASGISendEvent:
        """
        Buffering in memory helps avoid the 400 response ("There was an error parsing the body").
        <https://github.com/florimondmanca/msgpack-asgi/issues/11#issuecomment-1801288070>
        """
        body = b''
        more_body = True
        while more_body:
            message = await receive()
            body += message.get('body', b'')
            more_body = message.get('more_body', False)
        message["body"] = body
        message["more_body"] = False
        return message

    def _get_form_token(self, message: ASGISendEvent) -> str:
        """
        This approach is sub-optimal; ideally, there should be a 
        data structure to handle this, but I haven't found one yet.
        """
        body = message["body"].decode("utf8")
        re_csrftoken = re.compile(r'csrftoken=(.*)')
        if match := re_csrftoken.search(body):
            return match.group(1)
        re_csrftoken2 = re.compile(r'name="csrftoken"\r\n\r\n(.*?)\r\n')
        if match := re_csrftoken2.search(body):
            return match.group(1)

    async def __call__(self, scope: HTTPScope, receive: ASGIReceiveCallable, send: ASGISendCallable):
        if scope["type"] != "http":  # pragma: no cover
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        headers = MutableHeaders(scope=scope)
        cookie_name = self.cookie_name

        if request.method in SAFE_HTTP_METHODS:
            token = request.cookies.get(cookie_name)
            token_required = token is None

            if token_required:
                token = self.get_new_token()

            headers.update({
                "csrftoken": token,
                "csrf_cookie_name": cookie_name,
            })

            async def inner_send(message: ASGISendEvent):
                """
                `and scope["path"] not in self.exempt_urls_for_get` will handle
                the case where the first request from the user is to the urls
                of formview. In this case, the cookie should be set by the
                formview directly.
                """
                if message["type"] == "http.response.start":
                    if token_required and token and scope["path"] not in self.exempt_urls_for_get:
                        _headers = MutableHeaders(scope=message)
                        cookie: http.cookies.BaseCookie = http.cookies.SimpleCookie()
                        cookie[cookie_name] = token
                        cookie[cookie_name]["max-age"] = self.max_age
                        _headers.append(
                            "set-cookie", cookie.output(header="").strip())
                await send(message)
            await self.app(scope, receive, inner_send)
            return
        else:
            cookie_token = request.cookies.get(cookie_name)

            if not cookie_token:
                response = self._get_error_response(
                    "No CSRF cookie found", 403)
                await response(scope, receive, send)
                return

            header_token = None
            if self.allow_header_param:
                header_token = request.headers.get(self.header_name)

            form_token = None
            if self.allow_form_param and not header_token:
                message = await self._extract_message(receive)
                form_token = self._get_form_token(message)

            if not header_token and not form_token:
                response = self._get_error_response(
                    "The CSRF token wasn't found in the form data or header.", 403)
                await response(scope, receive, send)
                return

            if header_token and (cookie_token != header_token):
                response = self._get_error_response(
                    "The CSRF token in the header doesn't match the cookie.",
                    status_code=403,
                )
                await response(scope, receive, send)
                return

            if form_token and (cookie_token != form_token):
                response = self._get_error_response(
                    "The CSRF token in the form doesn't match the cookie.",
                    status_code=403,
                )
                await response(scope, receive, send)
                return

            # Provides defence in depth:
            # if request.base_url.is_secure:
            if request.base_url.is_secure:
                # According to this paper, the referer header is present in
                # the vast majority of HTTPS requests, but not HTTP requests,
                # so only check it for HTTPS.
                # https://seclab.stanford.edu/websec/csrf/csrf.pdf
                if not self.is_valid_referer(request):
                    response = self._get_error_response(
                        "Referer or origin is incorrect", status_code=403
                    )
                    await response(scope, receive, send)
                    return

            headers.update({
                "csrftoken": cookie_token,
                "csrf_cookie_name": cookie_name,
            })

            async def inner_receive():
                return message

            await self.app(scope, inner_receive, send)
            return
