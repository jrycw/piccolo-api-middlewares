# piccolo-api-middlewares
This repository is a personal exercise focused on transitioning the middlewares within the `Piccolo API` from the `async def dispatch(self, request, call_next)` style to `async def __call__(self, scope, receive, send)`.

## Procedures
Here are some general procedures for transforming the middleware:

1. The middleware no longer needs to inherit from `starlette.middleware.base.BaseHTTPMiddleware`. Instead, replace `super().__init__(app)` with `self.app = app`.

2. Remove the `dispatch` method.

3. Add the `__call__` method, a Python dunder method, with the signature `async def __call__(self, scope, receive, send)`.

4. Retrieve required information from the `scope` (a dictionary). `Starlette` provides helpful functions or data structures for this purpose. For example, the `request` object can be obtained from `request = starlette.requests.Request(scope)`.

5. Instead of directly returning the response, obtain a response, call it with `scope, receive, send`, `await` it, and then forcefully `return`.

6. `receive` and `send` are callable. Core business logic may need to be moved into these callables.

7. Finally, remember to call `self.app` with `scope, receive, send`, `await` it, and then forcefully `return`.

8. If you're open to adding the dependency, [asgiref](https://github.com/django/asgiref/) provides some useful type annotations.

## References
* [piccolo-api](https://piccolo-api.readthedocs.io/en/latest/)
* [starlette](https://www.starlette.io/middleware/)
* [starlette-csrf](https://github.com/frankie567/starlette-csrf/tree/main)
* [encode](https://www.encode.io/articles/working-with-http-requests-in-asgi)
* [How to secure APIs built with FastAPI: A complete guide](https://escape.tech/blog/how-to-secure-fastapi-api/#how-to-secure-fastapi-api-against-csrf)
