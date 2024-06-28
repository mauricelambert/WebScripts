def hello(
    environ, user, configuration, filename, arguments, inputs, csrf_token=None
):
    return "200 OK", {"Content-Type": "text/plain"}, f"Hello {user.name} !"


def page_500(error):
    return (
        error,
        {"Content-Type": "text/html; charset=utf-8"},
        [b"<h1>ERROR 500</h1><br><br>\n\n", error.encode()],
    )


def page_401(error):
    return (
        error,
        {"Content-Type": "text/html; charset=utf-8"},
        [b"<h1>ERROR 401</h1><br><br>\n\n", error.encode()],
    )


def page_403(error):
    return (
        error,
        {"Content-Type": "text/html; charset=utf-8"},
        [b"<h1>ERROR 403</h1><br><br>\n\n", error.encode()],
    )


def page_404(error):
    return (
        error,
        {"Content-Type": "text/html; charset=utf-8"},
        [b"<h1>ERROR 404</h1><br><br>\n\n", error.encode()],
    )
