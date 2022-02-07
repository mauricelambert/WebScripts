#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file tests the Errors.py file
#    from the command line and display the result in a web interface.
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
This file tests the Errors.py file
"""

from unittest import TestCase, main
from os import path
import sys

# sys.path = [path.join(path.dirname(__file__), ".."), *sys.path]
# sys.path.append(path.join(path.dirname(__file__), ".."))

WebScripts_path = path.join(path.dirname(__file__), "..")

if WebScripts_path not in sys.path:
    sys.path.insert(0, WebScripts_path)

from WebScripts.Errors import (
    WebScriptsError,
    WebScriptsConfigurationError,
    WebScriptsConfigurationTypeError,
    WebScriptsArgumentError,
    ScriptConfigurationError,
    MissingAttributesError,
    WebScriptsSecurityError,
)


class TestErrors(TestCase):
    def test_WebScriptsError(self):
        with self.assertRaises(WebScriptsError):
            raise WebScriptsError("test")

    def test_WebScriptsConfigurationError(self):
        with self.assertRaises(WebScriptsConfigurationError):
            raise WebScriptsConfigurationError("test")

    def test_WebScriptsConfigurationTypeError(self):
        with self.assertRaises(WebScriptsConfigurationTypeError):
            raise WebScriptsConfigurationTypeError("test")

    def test_WebScriptsArgumentError(self):
        with self.assertRaises(WebScriptsArgumentError):
            raise WebScriptsArgumentError("test")

    def test_ScriptConfigurationError(self):
        with self.assertRaises(ScriptConfigurationError):
            raise ScriptConfigurationError("test")

    def test_MissingAttributesError(self):
        with self.assertRaises(MissingAttributesError):
            raise MissingAttributesError("test")

    def test_WebScriptsSecurityError(self):
        with self.assertRaises(WebScriptsSecurityError):
            raise WebScriptsSecurityError("test")


if __name__ == "__main__":
    main()
