# from werkzeug.middleware.dispatcher import DispatcherMiddleware
# from main import app  # tu main.py
#
# application = DispatcherMiddleware(
#     None,
#     {
#         '/todo-project': app
#     }
# )

from main import app

application = app
