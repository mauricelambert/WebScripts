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

This file implements a CGI server to customize resquests
and responses with non-python script or executable.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file implements a CGI server to customize resquests
and responses with non-python script or executable.
"""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

from typing import TypeVar, Dict, List, Tuple
from subprocess import Popen, PIPE # nosec
from os.path import join, dirname
from os import _Environ
from json import dumps
from io import BytesIO

Server = TypeVar("Server")
User = TypeVar("User")


def bin(
    environ: _Environ,
    user: User,
    server: Server,
    script_name: str,
    arguments: Dict[str, Dict[str, str]],
    inputs: List[str],
    csrf_token: str = None,
) -> Tuple[str, Dict[str, str], str]:

    """
    This function reloads the configuration.
    """

    logs = server.logs
    debug = logs.debug

    debug(f"Call CGI function with script: {script_name!r}...")
    decoded_query = environ["QUERY_STRING"].replace("+", " ")

    for directory in server.configuration.cgi_path:
        script_path = server.research_filename(
            join(directory, script_name), no_error=True
        )
        if script_path is not None:
            break
    else:
        return "404", None, None

    debug("Build script and get launcher...")
    script = server.CommonsClasses.ScriptConfig()
    script.dirname = dirname(script_path)
    script.path = script_path
    script.name = script_name
    script.set_defaults()

    script_dict = script.get_dict()
    launcher = script.get_Windows_default_script_launcher(script_dict)

    debug(f"Build the command for {script_path!r}...")
    if launcher is not None:
        command = [launcher, script_path]
    else:
        command = [script_path]

    if "=" not in decoded_query:
        command.append(decoded_query)

    logs.warning(f"CGI script launch with: {command}")
    process = Popen(
        command,
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        shell=False,  # nosec
        env=server.get_environ_strings(environ, user, script),
    )

    debug("Send inputs and get outputs...")
    if isinstance(arguments, bytes):
        stdout, stderr = process.communicate(arguments)
    else:
        stdout, stderr = process.communicate(dumps(arguments).encode())

    stdout = BytesIO(stdout)

    header = True
    headers = {}

    debug("Get headers...")
    while header:
        header = stdout.readline()

        if not header.strip():
            break

        if b":" not in header:
            continue

        name, value = header.split(b":", 1)
        headers[name.strip().decode("ascii", "ignore")] = value.strip().decode(
            "ascii", "ignore"
        )

    debug("Get output...")
    if server.debug:
        output = stdout.read() + stderr
    else:
        output = stdout.read()

    stdout.close()

    code = process.returncode
    logs.info(f"Script exit code: {code}")

    if code:
        return (
            "500 Internal Server Error",
            headers,
            b"There is an error in the script execution." + output,
        )

    return "200 OK", headers, output
