import sys
import os

# Set root dir in Python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app

class VercelPathFixer:
    """
    Normalizes PATH_INFO when Vercel rewrites requests to /api/index
    so Flask routes like '/', '/login', '/admin/dashboard' match seamlessly.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')
        if path.startswith('/api/index.py'):
            environ['PATH_INFO'] = path.replace('/api/index.py', '', 1) or '/'
        elif path.startswith('/api/index'):
            environ['PATH_INFO'] = path.replace('/api/index', '', 1) or '/'
        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelPathFixer(app.wsgi_app)
