# piccolo-api-middlewares
This repository is a personal exercise focused on transitioning the middlewares within the `Piccolo API` from the `async def dispatch(self, request, call_next)` style to `async def __call__(self, scope, receive, send)`.

## References
* [piccolo-api](https://piccolo-api.readthedocs.io/en/latest/)
* [starlette](https://www.starlette.io/middleware/)
* [starlette-csrf](https://github.com/frankie567/starlette-csrf/tree/main)
* [encode](https://www.encode.io/articles/working-with-http-requests-in-asgi)
* [How to secure APIs built with FastAPI: A complete guide](https://escape.tech/blog/how-to-secure-fastapi-api/#how-to-secure-fastapi-api-against-csrf)
