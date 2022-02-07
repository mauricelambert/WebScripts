#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file tests the Pages.py file
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

"""
This file tests the Pages.py file
"""

from unittest.mock import MagicMock, patch, Mock
from unittest import TestCase, main
from subprocess import PIPE
from os import path
import sys

WebScripts_path = path.join(path.dirname(__file__), "..")

if WebScripts_path not in sys.path:
    sys.path.insert(0, WebScripts_path)

from WebScripts.Pages import (
    Pages,
    execute_scripts,
    check_right,
    get_environ,
)

from WebScripts import Pages as Module


class TestFunctions(TestCase):
    def test_execute_scripts(self):
        Pages.scripts = {}
        out, err, key, code, error = execute_scripts(
            "test", None, None, None, None
        )
        self.assertIsNone(out)
        self.assertIsNone(key)
        self.assertEqual(b"404", err)
        self.assertEqual(-1, code)
        self.assertEqual("Not Found", error)

        Pages.scripts = {"test": "test2"}

        with patch.object(
            Module,
            "check_right",
            return_value=False,
        ) as mock_method:

            out, err, key, code, error = execute_scripts(
                "test", "User", None, None, None
            )

            mock_method.assert_called_once_with("User", "test2")

        self.assertIsNone(out)
        self.assertIsNone(key)
        self.assertEqual(b"403", err)
        self.assertEqual(-1, code)
        self.assertEqual("Forbidden", error)

        script = Mock(path="path", launcher=None)
        Pages.scripts = {"test": script}

        with patch.object(
            Module,
            "get_environ",
            return_value={"test": "test1"},
        ) as m_get_environ, patch.object(
            Module, "Popen", return_value="process"
        ) as m_popen, patch.object(
            Module,
            "start_process",
            return_value=("stdout", "stderr", "key", "error", "code"),
        ) as m_start_process, patch.object(
            Module, "execution_logs"
        ) as m_logs:

            out, err, key, code, error = execute_scripts(
                "test",
                "User",
                {"test": "test"},
                ["abc"],
                ["def"],
                True,
            )

            m_get_environ.assert_called_once_with(
                {"test": "test"}, "User", script
            )
            m_popen.assert_called_once_with(
                ["path", "abc"],
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE,
                shell=False,
                env={"test": "test1"},
            )
            m_start_process.assert_called_once_with(
                script, "process", "User", ["def"]
            )
            m_logs.assert_called_once_with(script, "User", "process", "stderr")

        self.assertEqual(out, "stdout")
        self.assertEqual(key, "key")
        self.assertEqual("stderr", err)
        self.assertEqual("code", code)
        self.assertEqual("error", error)

        script = Mock(path="path", launcher="launcher")
        Pages.scripts = {"test": script}

        with patch.object(
            Module,
            "get_environ",
            return_value={"test": "test1"},
        ) as m_get_environ, patch.object(
            Module, "Popen", return_value="process"
        ) as m_popen, patch.object(
            Module,
            "start_process",
            return_value=("stdout", "stderr", "key", "error", "code"),
        ) as m_start_process, patch.object(
            Module, "execution_logs"
        ) as m_logs:

            out, err, key, code, error = execute_scripts(
                "test",
                "User",
                {"test": "test"},
                ["abc"],
                ["def"],
                True,
            )

            m_get_environ.assert_called_once_with(
                {"test": "test"}, "User", script
            )
            m_popen.assert_called_once_with(
                ["launcher", "path", "abc"],
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE,
                shell=False,
                env={"test": "test1"},
            )
            m_start_process.assert_called_once_with(
                script, "process", "User", ["def"]
            )
            m_logs.assert_called_once_with(script, "User", "process", "stderr")

        self.assertEqual(out, "stdout")
        self.assertEqual(key, "key")
        self.assertEqual("stderr", err)
        self.assertEqual("code", code)
        self.assertEqual("error", error)


if __name__ == "__main__":
    main()
