#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool runs CLI scripts and displays output in a Web Interface.
#    Copyright (C) 2021, 2022, 2023  Maurice Lambert

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

"""
This tool runs CLI scripts and displays output in a Web Interface.

This file implement Pages (Api and Web system), script execution and right
system.
"""

__version__ = "2.0.3"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file implement Pages (Api and Web system), script execution and right
system.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Pages"]

from typing import Tuple, List, Dict, TypeVar, Iterable, Union
from subprocess import Popen, PIPE, TimeoutExpired  # nosec
from os import _Environ, path, environ as base_environ
from base64 import urlsafe_b64encode
from contextlib import suppress
from secrets import token_bytes
from json import dumps, loads
from string import printable
from fnmatch import fnmatch
from threading import Timer
from html import escape
from time import time

Server = TypeVar("Server")

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
        current_directory,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_arguments_count,
        # doRollover,
        # rotator,
        # namer,
        # Handler,
        get_real_path,
        get_encodings,
        WebScriptsSecurityError,
        WebScriptsArgumentError,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
        logger_debug,
        logger_info,
        logger_auth,
        logger_access,
        logger_response,
        logger_command,
        logger_warning,
        logger_error,
        logger_critical,
        check_file_permission,
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
        current_directory,
        log_trace,
        get_ip,
        Logs,
        get_file_content,
        get_arguments_count,
        # doRollover,
        # rotator,
        # namer,
        # Handler,
        get_real_path,
        get_encodings,
        WebScriptsSecurityError,
        WebScriptsArgumentError,
        WebScriptsConfigurationError,
        WebScriptsConfigurationTypeError,
        logger_debug,
        logger_info,
        logger_auth,
        logger_access,
        logger_response,
        logger_command,
        logger_warning,
        logger_error,
        logger_critical,
        check_file_permission,
    )


@log_trace
def execute_scripts(
    script_name: str,
    user: User,
    environ: _Environ,
    arguments: List[str],
    inputs: List[str],
    is_auth: bool = False,
) -> Tuple[bytes, bytes, str, int, str]:
    """
    This function execute script from script name and return output and
    errors.
    """

    script = Pages.scripts.get(script_name)

    if script is None:
        return None, b"404", None, -1, "Not Found"

    if not is_auth and not check_right(user, script):
        return None, b"403", None, -1, "Forbidden"

    arguments.insert(0, script.path)

    launcher = script.launcher
    if launcher is not None:
        arguments.insert(0, launcher)

    script_env = get_environ(environ, user, script)

    process = Popen(
        arguments,
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        shell=False,
        env=script_env,
    )  # nosec

    stdout, stderr, key, error, code = start_process(
        script, process, user, inputs
    )

    execution_logs(script, user, process, stderr)
    return stdout, stderr, key, code, error


@log_trace
def start_process(
    script: ScriptConfig, process: Popen, user: User, inputs: List[str]
) -> Tuple[bytes, bytes, str, str, int]:
    """
    This function starts a process.
    """

    error = "No errors"

    if getattr(script, "print_real_time", None):
        key = urlsafe_b64encode(token_bytes(40)).decode()
        process_ = Pages.processes[key] = Process(process, script, user, key)
        process_.send_inputs(inputs)
        logger_debug(
            "Create key and process, sent inputs and get the first line."
        )
        return b"", b"", key, None, None

    try:
        stdout, stderr = process.communicate(
            input="\n".join(inputs).encode("latin-1"),
            timeout=script.timeout,
        )
    except TimeoutExpired:
        logger_error(f"TimeoutExpired on {script.name} for {user.name}")
        process.kill()

        stdout, stderr = process.communicate()
        error = "TimeoutError"

    return stdout, stderr, None, error, process.returncode


@log_trace
def anti_XSS(json_value: JsonValue) -> JsonValue:
    """
    This function clean a JSON object.
    """

    if isinstance(json_value, str):
        return escape(json_value)
    elif isinstance(json_value, int):
        return json_value
    elif isinstance(json_value, list):
        return [anti_XSS(value) for value in json_value]
    elif isinstance(json_value, dict):
        return {
            attribut: anti_XSS(value) for attribut, value in json_value.items()
        }
    elif json_value is None:
        return json_value
    else:
        raise NotImplementedError(
            f"type({type(json_value)}) is not implemented, supported types "
            "are: \n\t - str\n\t - int\n\t - list\n\t - dict\n\t - NoneType"
        )


@log_trace
def execution_logs(
    script: ScriptConfig, user: User, process: Popen, stderr: bytes
) -> None:
    """
    This function logs the script execution.
    """

    if script.no_password:
        logger_command(f"Command: {process.args}")

    if process.returncode or stderr:
        logger_error(
            f"SCRIPT ERROR: script {script.name!r} user {user.name!r} code "
            f"{process.returncode} STDERR {decode_output(stderr)}"
        )
    else:
        logger_debug(
            f"SCRIPT {script.name!r} executed without error for "
            f"user named {user.name!r}."
        )


@log_trace
def get_environ(
    environ: _Environ, user: User, script: ScriptConfig
) -> Dict[str, str]:
    """
    This function builds the environment variables for the new process.
    """

    for var_name, value in environ.items():
        if var_name not in base_environ:
            environ

    script_env = {
        key: (
            str(value)
            if key in base_environ
            else "".join(x for x in str(value) if x in printable)
        )
        if key != "wsgi.version"
        else ".".join([str(version) for version in value])
        for key, value in environ.items()
        if key
        not in (
            "wsgi.run_once",
            "wsgi.input",
            "wsgi.errors",
            "wsgi.file_wrapper",
        )
    }

    user_dict = user.get_dict()
    user_dict.pop("csrf", None)
    user_dict.pop("check_csrf", None)
    script_env["USER"] = dumps(user_dict)
    script_env["SCRIPT_CONFIG"] = dumps(script.get_JSON_API())

    return script_env


@log_trace
def check_right(user: User, configuration: ScriptConfig) -> bool:
    """
    This function check rights for script/user and return boolean.
    """

    if (
        user.groups
        and configuration.access_groups
        and any(group in user.groups for group in configuration.access_groups)
    ):
        return check_categories_scripts_access(user, configuration)
    elif configuration.access_users and user.id in configuration.access_users:
        return check_categories_scripts_access(user, configuration)
    elif isinstance(configuration.minimum_access, int) and any(
        group >= configuration.minimum_access for group in user.groups
    ):
        return check_categories_scripts_access(user, configuration)
    elif all(
        v is None
        for v in (
            configuration.minimum_access,
            configuration.access_users,
            configuration.access_groups,
        )
    ):
        return check_categories_scripts_access(user, configuration)
    else:
        logger_error(
            f"HTTP 403: Access denied for {user.name} on {configuration.name}"
        )
        return False


@log_trace
def check_categories_scripts_access(
    user: User, configuration: ScriptConfig
) -> bool:
    """
    This function check access on script and categories.
    """

    if any(
        [fnmatch(configuration.category, access) for access in user.categories]
    ):
        logger_info(
            f"{user.name} get access to category {configuration.category}"
            f" ({user.categories})"
        )
        return True
    elif any([fnmatch(configuration.name, access) for access in user.scripts]):
        logger_info(
            f"{user.name} get access to script {configuration.name}"
            f" ({user.scripts})"
        )
        return True
    else:
        logger_error(
            f"HTTP 403: {user.name} doesn't match with category "
            f"({configuration.category}) and script ({configuration.name})"
        )
        return False


@log_trace
def decode_output(data: bytes) -> str:
    """
    This function decodes outputs (try somes encoding).
    """

    output = None
    encodings = get_encodings()
    encoding = next(encodings)

    while encoding is not None:
        with suppress(UnicodeDecodeError):
            output = data.decode(encoding)
            return output

        encoding = next(encodings)


class Process:

    """
    This class implements a running processus.
    """

    def __init__(
        self, process: Popen, script: ScriptConfig, user: User, key: str
    ):
        logger_debug("Process creation...")
        self.process = process
        self.script = script
        self.user = user
        self.key = key
        self.start_time = time()
        self.timeout = script.timeout

        self.error = "No errors"

        if script.timeout is not None:
            logger_info("Timeout detected, make timer and start it.")
            self.timer = Timer(script.timeout, self.get_line, args=(False,))
            self.stop_max_time = self.start_time + self.timeout
            self.timer.start()

    def get_line(self, read: bool = True) -> Tuple[bytes, bytes, str]:
        """
        This function gets a new line from the script execution.
        """

        self.process.stdout.flush()
        if self.process.poll() is not None:
            if self.key in Pages.processes:
                del Pages.processes[self.key]

            self.timer.cancel()

            stdout = self.process.stdout
            stderr = self.process.stderr

            out = stdout.read()
            error = stderr.read()

            stdout.close()
            stderr.close()

            return (
                out,
                error,
                self.error,
            )

        elif self.timeout is None or time() <= self.stop_max_time:
            data = self.process.stdout.readline()
            logger_debug(
                f"Get new line on {self.script.name} for {self.user.name}"
            )
            return data, b"", ""
        else:
            logger_error(
                f"TimeoutExpired on {self.script.name} for {self.user.name}"
            )
            self.process.kill()

            if read:
                fdout = self.process.stdout
                fderr = self.process.stderr
                stdout = fdout.read()
                stderr = fderr.read()
                fdout.close()
                fderr.close()
                del Pages.processes[self.key]
            else:
                self.timer = Timer(300, self.get_line)
                # delete the process 5 minutes after the timeout
                self.timer.start()
                stdout = b""
                stderr = b""

            self.error = "TimeoutError"
            logger_debug("Get the stdout and the stderr of the killed process")

            return stdout, stderr, self.error

    def send_inputs(self, inputs: List[str]) -> None:
        """
        This function send inputs to the child process.
        """

        self.process.stdin.flush()
        for input_ in inputs:
            self.process.stdin.write(f"{input_}\n".encode("latin-1"))
            self.process.stdin.flush()

        self.process.stdin.close()
        logger_debug(
            "Inputs are sent to the child process and the stdin is closed."
        )


class Script:

    """
    This class groups script functions.
    """

    @log_trace
    def get(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[str, bytes]]:
        """
        This method send a new line of script execution in API response.
        """

        process = Pages.processes.get(filename)

        if process is None:
            logger_error(
                f"HTTP 404 for {user.name} on " f"/api/script/get/{filename}"
            )
            return "404", {}, b""

        if process.user.id != user.id:
            logger_error(
                f"HTTP 403 for {user.name} on "
                f"/api/script/get/{process.script.name}"
            )
            return "403", {}, b""

        stdout, stderr, error = process.get_line()
        code = process.process.returncode

        response_object = {
            "stdout": decode_output(stdout) if stdout else "",
            "stderr": decode_output(stderr) if stderr else "",
            "code": code,
            "Content-Type": process.script.content_type,
            "Stderr-Content-Type": (process.script.stderr_content_type),
            "error": error,
        }

        if code is None:
            response_object["key"] = filename

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            dumps(response_object),
        )


class Api:

    """
    This class groups API functions.
    """

    script: Script = Script()

    @log_trace
    def __call__(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        """
        This function return a json string with script informations and
        arguments.
        """

        server_configuration = server.configuration

        has_auth = (
            server_configuration.auth_script
            and server_configuration.active_auth
        )
        unauthenticated_not_accepted = (
            not server_configuration.accept_unknow_user and user.id == 1
        ) or (
            not server_configuration.accept_unauthenticated_user
            and user.id == 0
        )

        if has_auth:
            auth_script = Pages.scripts[
                server_configuration.auth_script
            ].get_JSON_API()
            auth_script["name"] = "/auth/"
            auth_script["category"] = "Authentication"

            scripts = {"/auth/": auth_script}
        else:
            scripts = {}

        if unauthenticated_not_accepted:
            return (
                "200 OK",
                {"Content-Type": "application/json; charset=utf-8"},
                dumps(scripts),
            )

        for name, script in Pages.scripts.items():
            if name == server_configuration.auth_script:
                continue

            if check_right(user, script):
                scripts[name] = script.get_JSON_API()

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            dumps(scripts),
        )

    @log_trace
    def scripts(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[str, bytes]]:
        """
        This function execute scripts with command line,
        get output, build the response error, headers and body
        and return it as json.
        """

        server_configuration = server.configuration

        if filename == server_configuration.auth_script:
            logger_error(
                f"HTTP 404 for {user.name} on /api/scripts/{filename}"
                " (auth script)"
            )
            return "404", {}, b""

        environ_getter = environ.get
        if user.check_csrf and not TokenCSRF.check_csrf(
            user,
            csrf_token,
            getattr(server_configuration, "csrf_max_time", 300),
            environ_getter("HTTP_REFERER"),
            server.get_baseurl(environ_getter, environ),
        ):
            logger_error(
                f"HTTP 403 for {user.name} on /api/scripts/{filename}"
                " (CSRF Token invalid)"
            )
            return "403", {}, b""

        stdout, stderr, key, code, error = execute_scripts(
            filename, user, environ, command, inputs
        )

        if stdout is None:
            error_HTTP = stderr.decode()
            logger_error(
                f"HTTP {error_HTTP} for {user.name} on "
                f"/api/scripts/{filename}"
            )
            return error_HTTP, {}, b""

        script = Pages.scripts[filename]

        response_object = {
            "stdout": decode_output(stdout) if stdout else "",
            "stderr": decode_output(stderr) if stderr else "",
            "code": code,
            "Content-Type": script.content_type,
            "Stderr-Content-Type": (script.stderr_content_type),
            "error": error,
        }

        if key:
            response_object["key"] = key

        if user.check_csrf:
            response_object["csrf"] = TokenCSRF.build_token(user)

        return (
            "200 OK",
            {"Content-Type": "application/json; charset=utf-8"},
            dumps(response_object),
        )


class Web:

    """
    This class groups Web Pages functions.
    """

    @log_trace
    def __call__(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        """
        This function return the index page (error code, headers, content).
        """

        return (
            "200 OK",
            {
                "Content-Security-Policy": (
                    "default-src 'self'; navigate-to 'self'; worker-src 'none'"
                    "; style-src-elem 'self'; style-src-attr 'none'; style-src"
                    " 'self'; script-src-attr 'none'; object-src 'none'; "
                    "media-src 'none'; manifest-src 'none'; frame-ancestors "
                    "'none'; connect-src 'self'; font-src 'none'; img-src "
                    "'self'; base-uri 'none'; child-src 'none'; form-action "
                    "'none'; script-src 'self' 'require-trusted-types-for'"
                )
            }
            if server.security
            else {
                "Content-Security-Policy-Report-Only": (
                    "default-src 'self'; navigate-to 'self'; worker-src "
                    "'none'; style-src-elem 'self'; style-src-attr 'none';"
                    " style-src 'self'; script-src-attr 'none'; object-src"
                    " 'none'; media-src 'none'; manifest-src 'none'; "
                    "frame-ancestors 'none'; connect-src 'self'; font-src"
                    " 'none'; img-src 'self'; base-uri 'none'; child-src"
                    " 'none'; form-action 'none'; script-src 'self' "
                    "'require-trusted-types-for'; report-uri /csp/debug/"
                )
            },
            (
                CallableFile.template_index
                if server.security
                else CallableFile.template_index.replace(
                    "Content-Security-Policy",
                    "Content-Security-Policy-Report-Only",
                )
            )
            % {
                "footer": CallableFile.template_footer,
                "header": CallableFile.template_header,
            },
        )

    @log_trace
    def doc(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[str, bytes, Iterable[bytes]]]:
        """
        This function return Web Page with scripts documentation.
        """

        script = Pages.scripts.get(filename)

        if script is None:
            logger_error(f"HTTP 404 for {user.name} on /web/doc/{filename}")
            return "404", {}, b""

        if not check_right(user, script):
            logger_error(
                f"HTTP 403: Access denied for {user.name} on {filename} "
                "(/web/doc/ request)"
            )
            return "403", {}, b""

        command_template = script.command_generate_documentation
        if command_template is not None:
            command = command_template % script.get_dict()
            logger_command(f"Command for documentation: {command!r}")
            process = Popen(  # nosec # nosemgrep
                command,
                env=get_environ(environ, user, script),
                shell=True,  # nosec # nosemgrep
            )  # nosec # nosemgrep
            process.communicate()

        docfile = get_real_path(script.documentation_file)
        if docfile is not None and path.isfile(docfile):
            return (
                "200 OK",
                {
                    "Content-Type": f"{script.documentation_content_type};"
                    " charset=utf-8"
                },
                get_file_content(docfile, as_iterator=True),
            )
        else:
            doc = ScriptConfig.get_docfile_from_configuration(
                server.configuration, filename
            )

            if doc is not None:
                return (
                    "200 OK",
                    {
                        "Content-Type": f"{script.documentation_content_type};"
                        " charset=utf-8"
                    },
                    get_file_content(doc, as_iterator=True),
                )

        logger_error(f"HTTP 404 for {user.name} on /web/doc/{filename}")
        return "404", {}, b""

    @log_trace
    def scripts(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[bytes, str, Iterable[bytes]]]:
        """
        This function return Web (HTML) response
        (error code, headers and page) to call script
        and print script output
        """

        server_configuration = server.configuration

        if filename == server_configuration.auth_script:
            logger_error(
                f"HTTP 404 for {user.name} on /web/scripts/{filename}"
                " (auth script)"
            )
            return "404", {}, b""

        script = Pages.scripts.get(filename)

        if script is None:
            logger_error(
                f"HTTP 404 for {user.name} on /web/scripts/{filename}"
            )
            return "404", {}, b""

        if not check_right(user, script):
            logger_error(
                f"HTTP 403: Access denied for {user.name} on {filename}"
                " (/web/scripts/ request)"
            )
            return "403", {}, b""

        callable_file = CallableFile(
            "script", filename, filename, security=server.security
        )

        if callable_file is not None:
            return callable_file(user)

        logger_error(f"HTTP 404 for {user.name} on /web/scripts/{filename}")
        return "404", {}, b""

    @log_trace
    def auth(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[bytes, Iterable[bytes]]]:
        """
        This function returns authentication page (URL: /web/auth/).
        """

        server_configuration = server.configuration

        if server_configuration.active_auth:
            code, headers, content = CallableFile(
                "script", server_configuration.auth_script, "/auth/"
            )(user, len(environ["PATH_INFO"].split("/")) - 1)
            return code, headers, content
        else:
            logger_error(
                f"HTTP 404 for {user.name} on /web/auth/ (active_auth"
                " configuration is not True)"
            )
            return "404", {}, b""


class Pages:

    """
    This class implement Web Pages for WebScripts server.
    """

    packages: DefaultNamespace
    scripts: Dict[str, ScriptConfig]
    js_paths: Dict[str, CallableFile]
    statics_paths: Dict[str, CallableFile]
    sessions: Dict[int, Session] = {}
    ip_blacklist: Dict[str, Blacklist] = {}
    user_blacklist: Dict[str, Blacklist] = {}
    processes: Dict[str, Process] = {}
    api = Api()
    web = Web()

    def __call__(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], bytes]:
        """
        A redirect page (Error code 301, javascript redirect and redirect
        title) to /web/ or /api/.
        """

        return (
            "301 Moved Permanently",
            {"Location": "/web/"},
            b"<!-- To use API go to this URL: /api/ --><html><body><h1>"
            b'Index page is /web/</h1><a href="/web/">Please click here'
            b'</a><script>window.location="/web/"</script></html>',
        )

    @staticmethod
    @log_trace
    def webfile(
        files: Dict[str, CallableFile], user: User, filename: str, base: str
    ) -> Tuple[str, Dict[str, str], Union[bytes, Iterable[bytes]]]:
        """
        This function builds response for Web files.
        """

        callable_file = files.get(filename, None)

        if callable_file is not None:
            return callable_file(user)

        logger_error(f"HTTP 404 for {user.name!r} on /{base}/{filename}")
        return "404", {}, b""

    @log_trace
    def js(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[bytes, Iterable[bytes]]]:
        """
        This function get Javascripts Scripts and send it.
        """

        return self.webfile(Pages.js_paths, user, filename, "js")

    @log_trace
    def static(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], Union[bytes, Iterable[bytes]]]:
        """
        This function get static file and send it.
        """

        return self.webfile(Pages.statics_paths, user, filename, "static")

    @log_trace
    def auth(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], bytes]:
        """
        This function return check auth and return headers, error and page.
        """

        ip = environ["REMOTE_IP"]
        server_configuration = server.configuration

        if not server_configuration.active_auth:
            logger_error(
                f"HTTP 403: Access denied for {user.name} on /auth/ "
                "(active_auth configuration is not True)"
            )
            return "403", {}, b""

        logger_info("Run authentication script.")
        stdout, stderr, key, code, error = execute_scripts(
            server_configuration.auth_script,
            user,
            environ,
            command,
            inputs,
            is_auth=True,
        )

        if len(stderr) == 3:
            return stderr.decode(), {}, b""

        if code or stdout is None or stderr:
            return "500", {}, b""

        user = User.default_build(**anti_XSS(loads(stdout)))

        if user.id != 0:
            Pages.ip_blacklist[ip] = Blacklist(
                server_configuration, Pages.ip_blacklist.pop(ip, None)
            )
            if "--username" in command:
                user_index = command.index("--username") + 1
                username = command[user_index]
                Pages.user_blacklist[username] = Blacklist(
                    server_configuration,
                    Pages.user_blacklist.pop(username, None),
                )
            logger_auth(
                f"{user.name!r} ({user.id}) successfully authenticated"
                f" from {ip} on {environ['PATH_INFO']}"
            )

        cookie = Session.build_session(user, ip, Pages)

        return (
            "302 Found",
            {
                # "Location": "/web/",
                "Set-Cookie": f"SessionID={cookie}; Path=/; SameSite=Strict;"
                f""" Max-Age={getattr(
                    server_configuration,
                    'session_max_time',
                    3600)}; Secure; HttpOnly""",
            },
            b"",
        )

    def reload(
        self,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        command: List[str],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        """
        This function is a simple URL to reload scripts
        (useful for developpers to add/modify a script).
        """

        pass
