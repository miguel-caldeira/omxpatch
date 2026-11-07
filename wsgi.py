"""Ponto de entrada WSGI (gunicorn/uwsgi, IIS + wfastcgi): ``wsgi:app``.

Com vários processos web defina OMXPATCH_EMBEDDED_WORKER=false e execute ``omxpatch worker`` como serviço."""
from omxpatch import create_app

app = create_app()
application = app
