from .index import app


# Vercel entry point
def handler(request):
    return app(request.environ, lambda status, headers: None)