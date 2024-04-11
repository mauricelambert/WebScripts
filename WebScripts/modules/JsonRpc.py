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

This module implements JSON RPC on WebScripts.
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This module implements JSON RPC on WebScripts.
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

__all__ = ["JsonRpc"]

from typing import TypeVar, List, Tuple, Dict, Any, Union
from collections.abc import Callable
from os import _Environ
from json import dumps

Server = TypeVar("Server")
User = TypeVar("User")


def test_call() -> int:
    return 0


def test_argument_list(*args) -> str:
    return str([repr(a) for a in args])


def test_argument_dict(a: int = 1, b: int = 2) -> int:
    return a + b


class JsonRpc:
    """
    This class implements JSON RPC for the WebScripts Server.
    """

    functions: Dict[str, Callable] = {"call": test_call}

    @classmethod
    def register_function(cls: type, function: Callable, name: str = None):
        """
        This function adds a new function in the JSON RPC calls.
        """

        cls.functions[name or function.__name__] = function

    @classmethod
    def execute_call(cls: type, json: Dict[str, Any]) -> Dict[str, Any]:
        """
        This function performs a JSON RPC call.
        """

        id_ = json.get("id")
        params = json.get("params", [])

        print(
            isinstance(json, dict),
            json.get("jsonrpc") == "2.0",
            isinstance(id_, int),
        )
        if (
            not isinstance(json, dict)
            or json.get("jsonrpc") != "2.0"
            or not isinstance(id_, int)
        ):
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": "Invalid Request"},
                "id": None,
            }

        if not isinstance(params, (list, dict)):
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": "Invalid params"},
                "id": None,
            }

        method_name = json.get("method")

        if method_name not in cls.functions:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Method not found"},
                "id": id_,
            }

        if isinstance(params, list):
            try:
                return {
                    "jsonrpc": "2.0",
                    "result": cls.functions[method_name](*params),
                    "id": id_,
                }
            except Exception:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "Internal error"},
                    "id": id_,
                }
        else:
            try:
                return {
                    "jsonrpc": "2.0",
                    "result": cls.functions[method_name](**params),
                    "id": id_,
                }
            except Exception:
                return {
                    "jsonrpc": "2.0",
                    "error": {"code": -32603, "message": "Internal error"},
                    "id": id_,
                }

    def __new__(
        cls: type,
        environ: _Environ,
        user: User,
        server: Server,
        filename: str,
        calls: Union[List[Dict[str, Any]], Dict[str, Any]],
        inputs: List[str],
        csrf_token: str = None,
    ) -> Tuple[str, Dict[str, str], str]:
        execute_call = cls.execute_call
        if isinstance(calls, list):
            if not calls:
                return (
                    "400 Bad Request",
                    {"Content-Type": 'application/json; charset="utf-8"'},
                    '{"jsonrpc": "2.0", "error": {"code": -32600, '
                    '"message": "Invalid Request"}, "id": null}',
                )

            result = [execute_call(call) for call in calls]
        elif isinstance(calls, bytes):
            return (
                "400 Bad Request",
                {"Content-Type": 'application/json; charset="utf-8"'},
                '{"jsonrpc": "2.0", "error": {"code": -32700, '
                '"message": "Parse error"}, "id": null}',
            )
        else:
            result = execute_call(calls)

        return (
            "200 OK",
            {"Content-Type": 'application/json; charset="utf-8"'},
            dumps(result),
        )


# https://www.jsonrpc.org/specification

JsonRpc.register_function(test_argument_list)
JsonRpc.register_function(test_argument_dict, "test_args_dict")
