#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tool run scripts and display the result in a Web Interface.
#    Copyright (C) 2021, 2022  Maurice Lambert

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
This tool run scripts and display the result in a Web Interface.

This file implements a debug mode module to changes configurations
and reload modules.
"""

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool run scripts and display the result in a Web Interface.

This file implements a debug mode module to changes configurations
and reload modules.
"""
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

from importlib.util import spec_from_file_location  # , _find_spec_from_path
from typing import TypeVar, Dict, List, Tuple
from importlib import reload as module_reload
from json.decoder import JSONDecodeError
from collections import defaultdict
from urllib.parse import parse_qs
from contextlib import suppress
from urllib.parse import quote
from json import dumps, loads
from types import ModuleType
from os import _Environ
from html import escape

# from sys import modules

try:
    from _frozen_importlib import _exec  # ModuleSpec, _init_module_attrs,
except ImportError:
    from importlib._bootstrap import _exec  # ModuleSpec, _init_module_attrs,

Server = TypeVar("Server")
User = TypeVar("User")

NoneType = type(None)

# def my_exec(spec: ModuleSpec, module: ModuleType):
#     _init_module_attrs(spec, module, override=True)
#     if not hasattr(spec.loader, 'exec_module'):
#         spec.loader.load_module(name)
#     else:
#         spec.loader.exec_module(module)


class Reload:

    html: str = """
        <html><head><title>WebScripts Server configuration</title></head>
        <body><pre><code>{}</code></pre><br><label>Configuration:</label>
        <input id="conf" onload="change()" onchange="change()"><br>
        <form method="POST" action=""><label>Value:</label>
        <textarea id="value"></textarea><br><input type="submit"></form>
        <footer><script>
        function change () {{
            document.getElementById(
                'value'
            ).name = document.getElementById('conf').value;
        }}
        </script></footer></body></html>
    """

    accept_types: Tuple[type] = (list, NoneType, str, bool, int, float)
    simple_types: Tuple[type] = (NoneType, str, bool, int, float)

    def server(
        environ: _Environ,
        user: User,
        server: Server,
        name: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function reloads the configuration.
        """

        if arguments and isinstance(arguments, bytes):
            configuration = server.configuration
            builder = configuration.build_type
            values = parse_qs(arguments.decode("ascii", "ignore"))
            for name, values in values.items():
                value = values[-1]
                with suppress(JSONDecodeError):
                    value = loads(value)
                builder(name, value)

        accept_types = Reload.accept_types
        html = Reload.html.format(
            dumps(
                {
                    k: v
                    for k, v in server.configuration.__dict__.items()
                    if isinstance(v, accept_types)
                },
                indent=4,
            )
        )

        return "200 OK", {}, html

    def scripts(
        environ: _Environ,
        user: User,
        server: Server,
        name: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function reloads a script configuration.
        """

        script = server.pages.scripts.get(name)

        if script is None:
            return "404", {}, None

        if arguments and isinstance(arguments, bytes):
            builder = script.build_type
            values = parse_qs(arguments.decode("ascii", "ignore"))
            for name, values in values.items():
                value = values[-1]
                with suppress(JSONDecodeError):
                    value = loads(value)
                builder(name, value)

        simple_types = Reload.simple_types
        html = Reload.html.format(
            dumps(
                {
                    k: v
                    for k, v in script.get_dict().items()
                    if isinstance(v, simple_types)
                    or (
                        isinstance(v, list)
                        and all(isinstance(x, simple_types) for x in v)
                    )
                },
                indent=4,
            )
        )

        return "200 OK", {}, html

    def arguments(
        environ: _Environ,
        user: User,
        server: Server,
        name: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function reloads a argument configuration.
        """

        if "|" not in name:
            return "404", {}, None

        script_name, argument_name = name.split("|", 1)
        script = server.pages.scripts.get(script_name)

        if script is None:
            return "404", {}, None

        argument = [a for a in script.args if argument_name == a.name]

        if not argument:
            return "404", {}, None

        argument = argument[0]

        if arguments and isinstance(arguments, bytes):

            builder = argument.build_type
            values = parse_qs(arguments.decode("ascii", "ignore"))
            for name, values in values.items():
                value = values[-1]
                with suppress(JSONDecodeError):
                    value = loads(value)
                builder(name, value)

        # simple_types = Reload.simple_types
        html = Reload.html.format(dumps(argument.get_dict(), indent=4))

        return "200 OK", {}, html

    def modules(
        environ: _Environ,
        user: User,
        server: Server,
        name: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function adds new modules.
        """

        server.add_module_or_package()
        return (
            "200 OK",
            {"Content-Type": "text/plain"},
            "Modules successfully reloaded.",
        )

    def web(
        environ: _Environ,
        user: User,
        server: Server,
        name: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function reloads web files (JS, CSS and HTML).
        """

        server.add_paths()
        file = server.CommonsClasses.CallableFile
        research_filename = server.research_filename
        research_file_content = server.research_file_content

        template_script_path = file.template_script_path = research_filename(
            "static/templates/script.html"
        )
        template_header_path = file.template_header_path = research_filename(
            "static/templates/header.html"
        )
        template_footer_path = file.template_footer_path = research_filename(
            "static/templates/footer.html"
        )
        template_index_path = file.template_index_path = research_filename(
            "static/templates/index.html"
        )

        print(
            template_script_path,
            template_header_path,
            template_footer_path,
            template_index_path,
        )

        file.template_script: str = research_file_content(template_script_path)
        file.template_header: str = research_file_content(template_header_path)
        file.template_footer: str = research_file_content(template_footer_path)
        file.template_index: str = research_file_content(template_index_path)

        return (
            "200 OK",
            {"Content-Type": "text/plain"},
            "Web files successfully reloaded.",
        )

    def module(
        environ: _Environ,
        user: User,
        server: Server,
        name: str,
        arguments: Dict[str, Dict[str, str]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:

        """
        This function reloads a module.
        """

        packages = server.pages.packages.__dict__
        module = packages.get(name)
        print(module)

        if module is not None:

            try:
                packages[name] = module_reload(module)
                print("Reload", module)
            except ModuleNotFoundError:
                print(module._webscripts_filepath, name)
                spec = spec_from_file_location(
                    module._webscripts_filepath, name, loader=module.__loader__
                )
                # spec = _find_spec_from_path(name, module._webscripts_filepath)
                spec.name = name
                # my_exec(spec, module)
                print(name, module)
                _exec(spec, module)
                packages[name] = module

            server.pages_cache = defaultdict(lambda: (None, None))
            return (
                "200 OK",
                {"Content-Type": "text/plain"},
                "Module successfully reloaded.",
            )

        html = "<ul>"
        for name, module in packages.items():
            if isinstance(module, ModuleType):
                html += (
                    f'<li><a href="{quote(name)}">Reload: {escape(name)}'
                    "</a></li>"
                )

        return (
            "200 OK",
            {},
            html + "</ul>",
        )  # + '<br>'.join(repr(x) for x in modules.keys())
