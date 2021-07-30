#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This package implements a web server to run scripts or executables
#    from the command line and display the result in a web interface.
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

"""This package implements a web server to run scripts or 
executables from the command line and display the result 
in a web interface.

This file implement Pages (Api and Web system), script execution and right system."""

from subprocess import Popen, PIPE, TimeoutExpired
from os import _Environ, device_encoding, path
from typing import Tuple, List, Dict
import locale
import json

try:
    from .commons import (
        Argument,
        User,
        ScriptConfig,
        CallableFile,
        TokenCSRF,
        Blacklist,
        Session,
        JsonValue,
        ServerConfiguration,
        DefaultNamespace,
        get_ini_dict,
        lib_directory,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_real_path,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
    )
except ImportError:
    from commons import (
        Argument,
        User,
        ScriptConfig,
        CallableFile,
        TokenCSRF,
        Blacklist,
        Session,
        JsonValue,
        ServerConfiguration,
        DefaultNamespace,
        get_ini_dict,
        lib_directory,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_real_path,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
    )

__version__ = "0.0.4"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """This package implements a web server to run scripts or 
executables from the command line and display the result in a web interface.

This file implement Pages (Api and Web system), script execution and right system."""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

__all__ = ["Pages"]


def execute_scripts(
    script_name: str,
    user: User,
    environ: _Environ,
    arguments: List[str],
    inputs: List[str],
) -> Tuple[bytes, bytes]:

    """This function execute script from script name and return output and errors."""

    script = Pages.scripts.get(script_name)
    error = "No errors"

    if script is None:
        return None, b"404", -1, error

    if not check_right(user, script):
        return None, b"403", -1, error

    arguments.insert(0, script.path)

    if script.launcher is not None:
        arguments.insert(0, script.launcher)

    script_env = environ.copy()

    script_env["USER"] = json.dumps(user.get_dict())
    script_env["SCRIPT_CONFIG"] = json.dumps(script.get_JSON_API())

    to_delete = [
        key
        for key in script_env.keys()
        if key in ("wsgi.run_once", "wsgi.input", "wsgi.errors", "wsgi.file_wrapper")
    ]
    for key in to_delete:
        del script_env[key]

    script_env["wsgi.version"] = ".".join(
        [str(version) for version in script_env["wsgi.version"]]
    )
    script_env = {key:str(value) for key, value in script_env.items()}

    process = Popen(
        arguments, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False, env=script_env
    )

    try:
        stdout, stderr = process.communicate(
            input="\n".join(inputs).encode("latin-1"),
            timeout=script.timeout,
        )
    except TimeoutExpired:
        Logs.error(f"TimeoutExpired on {script.name} for {user.name}")
        process.kill()

        stdout, stderr = process.communicate()
        error = "TimeoutError"

    if process.returncode or stderr:
        Logs.error(
            f"SCRIPT ERROR: script {script.name} user {user.name} code {process.returncode} STDERR {stderr.decode('latin-1')}"
        )
    else:
        Logs.debug(
            f'SCRIPT "{script_name}" executed without error for user named "{user.name}".'
        )

    return stdout, stderr, process.returncode, error


def check_right(user: User, configuration: ScriptConfig) -> bool:

    """This function check rights for script/user and return boolean."""

    if (
        user.groups
        and configuration.access_groups
        and any(group in user.groups for group in configuration.access_groups)
    ):
        return True
    elif configuration.access_users and user.id in configuration.access_users:
        return True
    elif configuration.minimum_access and any(
        group >= configuration.minimum_access for group in user.groups
    ):
        return True
    elif all(
        v is None
        for v in (
            configuration.minimum_access,
            configuration.access_users,
            configuration.access_groups,
        )
    ):
        return True
    else:
        Logs.error(f"HTTP 403: Access denied for {user.name} on {configuration.name}")
        return False


def decode_output(data: bytes) -> str:

    """This function decode outputs (try somes encoding)."""

    output = None

    try:
        output = data.decode(locale.getpreferredencoding())
    except UnicodeDecodeError:
        pass
    else:
        return output

    try:
        output = data.decode(device_encoding(0))
    except UnicodeDecodeError:
        pass
    else:
        return output

    try:
        output = data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    else:
        return output

    try:
        output = data.decode("latin-1")
    except UnicodeDecodeError:
        pass
    else:
        return output


class Api:

    """This class regroup api functions."""

    @log_trace
    def __call__(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function return a json string with script informations and arguments."""

        if server_configuration.auth_script and server_configuration.active_auth:
            auth_script = Pages.scripts[server_configuration.auth_script].get_JSON_API()
            auth_script["name"] = "/auth/"
            auth_script["category"] = "Authentication"

            scripts = {"/auth/": auth_script}
        else:
            scripts = {}

        for name, script in Pages.scripts.items():
            if name == server_configuration.auth_script:
                continue

            if check_right(user, script):
                scripts[name] = script.get_JSON_API()

        if (
            (not server_configuration.accept_unknow_user and user.id == 1)
            or (not server_configuration.accept_unauthenticated_user and user.id == 0)
        ) and server_configuration.active_auth:
            auth_script = Pages.scripts[server_configuration.auth_script].get_JSON_API()
            auth_script["name"] = "/auth/"
            auth_script["category"] = "Authentication"

            scripts = {"/auth/": auth_script}

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            json.dumps(scripts),
        )

    @log_trace
    def scripts(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function execute scripts with command line,
        get output, build the response error, headers and body
        and return it as json."""

        if filename == server_configuration.auth_script:
            Logs.error(
                f"HTTP 404 for {user.name} on /api/scripts/{filename} (auth script)"
            )
            return "404", {}, b""

        if user.check_csrf and not TokenCSRF.check_csrf(user, csrf_token):
            Logs.error(
                f"HTTP 403 for {user.name} on /api/scripts/{filename} (CSRF Token invalid)"
            )
            return "403", {}, b""

        stdout, stderr, code, error = execute_scripts(
            filename, user, environ, commande, inputs
        )

        if stdout is None:
            error_HTTP = stderr.decode()
            Logs.error(f"HTTP {error_HTTP} for {user.name} on /api/scripts/{filename}")
            return error_HTTP, {}, b""

        response_object = {
            "stdout": decode_output(stdout),
            "stderr": decode_output(stderr),
            "code": code,
            "Content-Type": Pages.scripts[filename].content_type,
            "error": error,
        }

        if user.check_csrf:
            response_object["csrf"] = TokenCSRF.build_token(user)

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            json.dumps(response_object),
        )


class Web:

    """This class regroup Web Pages functions."""

    @log_trace
    def __call__(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function return the index page (error code, headers, content)."""

        return (
            "200 OK",
            {
                "Content-Security-Policy": "default-src 'self'; form-action 'none'; script-src 'self' 'sha512-PrdxK6oDVtJdo252hYBGESefJT/X4juRfz9nEf9gFJ4JkLYYIkFqdmTUJ3Dj1Bbqt0yp5cwmUHsMYpCdGdSryg=='"
            },
            CallableFile.template_index,
        )

    @log_trace
    def doc(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function return Web Page with scripts documentation."""

        script = Pages.scripts.get(filename)

        if script is None:
            Logs.error(f"HTTP 404 for {user.name} on /web/doc/{filename}")
            return "404", {}, b""

        if not check_right(user, script):
            Logs.error(
                f"HTTP 403: Access denied for {user.name} on {filename} (/web/doc/ request)"
            )
            return "403", {}, b""

        if script.command_generate_documentation is not None:
            command = script.command_generate_documentation % script.get_dict()
            process = Popen(command, shell=True)
            process.communicate()

        docfile = get_real_path(script.documentation_file)
        if script.documentation_file is not None and path.isfile(docfile):
            return (
                "200 OK",
                {"Content-Type": f"{script.documentation_content_type}; charset=utf-8"},
                get_file_content(script.documentation_file),
            )
        else:
            doc = ScriptConfig.get_docfile_from_configuration(
                server_configuration, filename
            )

            if doc is not None:
                return (
                    "200 OK",
                    {
                        "Content-Type": f"{script.documentation_content_type}; charset=utf-8"
                    },
                    get_file_content(doc),
                )

        Logs.error(f"HTTP 404 for {user.name} on /web/doc/{filename}")
        return "404", {}, b""

    @log_trace
    def scripts(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """ "This function return Web (HTML) response (error code, headers and page)
        to call script and print script output"""

        if filename == server_configuration.auth_script:
            Logs.error(
                f"HTTP 404 for {user.name} on /web/scripts/{filename} (auth script)"
            )
            return "404", {}, b""

        script = Pages.scripts.get(filename)

        if script is None:
            Logs.error(f"HTTP 404 for {user.name} on /web/scripts/{filename}")
            return "404", {}, b""

        if not check_right(user, script):
            Logs.error(
                f"HTTP 403: Access denied for {user.name} on {filename} (/web/scripts/ request)"
            )
            return "403", {}, b""

        callable_file = CallableFile("script", filename, filename)

        if callable_file is not None:
            return callable_file(user)

        Logs.error(f"HTTP 404 for {user.name} on /web/scripts/{filename}")
        return "404", {}, b""

    @log_trace
    def auth(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function return authentication page."""

        if server_configuration.active_auth:
            callable_file = CallableFile(
                "script", server_configuration.auth_script, "/auth/"
            )
            return callable_file(user)
        else:
            Logs.error(
                f"HTTP 403 for {user.name} on /web/auth/ (active_auth configuration is not True)"
            )
            return "403", {}, b""


class Pages:

    """This class implement Web Pages for WebScripts server."""

    packages: DefaultNamespace
    scripts: Dict[str, ScriptConfig]
    js_paths: Dict[str, CallableFile]
    statics_paths: Dict[str, CallableFile]
    sessions: Dict[int, Session] = {}
    ip_blacklist: Dict[str, Blacklist] = {}
    user_blacklist: Dict[str, Blacklist] = {}
    api = Api()
    web = Web()

    def __call__(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """A redirect page (Error code 301, javascript redirect and redirect title) to /web/ or /api/."""

        return (
            "301 Moved Permanently",
            {"Location": "/web/"},
            '<!-- To use API go to this URL: /api/ --><html><body><h1>Index page is /web/</h1><a href="/web/">Please click here</a><script>window.location="/web/"</script></html>',
        )

    @log_trace
    def js(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function get Javascripts Scripts and send it."""

        callable_file = Pages.js_paths.get(filename, None)

        if callable_file is not None:
            return callable_file(user)

        Logs.error(f"HTTP 404 for {user.name} on /js/{filename}")
        return "404", {}, b""

    @log_trace
    def static(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function get static file and send it."""

        callable_file = Pages.statics_paths.get(filename, None)

        if callable_file is not None:
            return callable_file(user)

        Logs.error(f"HTTP 404 for {user.name} on /static/{filename}")
        return "404", {}, b""

    @log_trace
    def auth(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function return check auth and return headers, error and page."""

        ip = get_ip(environ)

        if not server_configuration.active_auth:
            Logs.error(
                f"HTTP 403: Access denied for {user.name} on /auth/ (active_auth configuration is not True)"
            )
            return "403", {}, b""

        Logs.info("Run authentication script.")
        stdout, stderr, code, error = execute_scripts(
            server_configuration.auth_script, user, environ, commande, inputs
        )

        if len(stderr) == 3:
            return stderr.decode(), {}, ""

        if code or stdout is None or stderr:
            return "500", {}, ""

        user = User.default_build(**json.loads(stdout))

        if user.id == 0:
            Pages.ip_blacklist[ip] = Blacklist(
                server_configuration, Pages.ip_blacklist.pop(ip, None)
            )
            if "--username" in commande:
                user_index = commande.index("--username") + 1
                username = commande[user_index]
                Pages.user_blacklist[username] = Blacklist(
                    server_configuration, Pages.user_blacklist.pop(username, None)
                )

        cookie = Session.build_session(user, get_ip(environ), Pages)

        return (
            "302 Found",
            {
                # "Location": "/web/",
                "Set-Cookie": f"SessionID={cookie}; Path=/; SameSite=Strict; Max-Age=3600; Secure; HttpOnly",
            },
            "",
        )

    def reload(
        self,
        environ: _Environ,
        user: User,
        server_configuration: ServerConfiguration,
        filename: str,
        commande: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """This function is a simple URL to reload scripts
        (useful for developpers to add/modify a script)."""

        pass
