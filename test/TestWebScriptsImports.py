#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This file test the WebScript.py file
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
This file tests specials imports with specific
variables values.
"""

from os import path, rename, chdir, getcwd
import logging.config
import logging
import sys

argv = sys.argv.copy()
sys.argv = ["WebScripts", "--test-running"]

dir_path = path.dirname(__file__)


def disable_logs():
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})
    logging.disable()


def import_without_package():
    ################
    # SAVE VARIABLES
    ################

    path_ = sys.path.copy()
    modules = sys.modules.copy()
    locals_ = locals().copy()
    globals_ = globals().copy()
    current_path = getcwd()
    dst1 = path.join(dir_path, "..", "WebScripts", "__init__.py")
    dst2 = path.join(dir_path, "..", "test", "init.py")

    ########################
    # CHANGE CONTEXT AND SYS
    ########################

    error = None

    try:
        for i in [0, 0, -1, -1]:
            sys.path.pop(i)

        rename(dst1, dst2)
        chdir(path.join(dir_path, "..", "WebScripts"))
        sys.path.insert(0, "")

        for name in [
            "WebScripts",
            "Configuration",
            "Server",
            "WebScriptsConfigurationTypeError",
            "commons",
            "Blacklist",
            "Session",
        ]:
            if name in locals().keys():
                del locals()[name]
            if name in globals().keys():
                del globals()[name]

        remove_names = []
        for name in sys.modules.keys():
            if "WebScripts." in name or name == "WebScripts":
                remove_names.append(name)

        for name in remove_names:
            del sys.modules[name]

        from WebScripts import (
            Configuration,
            Server,
            WebScriptsConfigurationTypeError,
        )
        from commons import Blacklist, Session

    except Exception as e:
        error = e

    #########################
    # REBUILD CONTEXT AND SYS
    #########################
    finally:
        sys.path = path_
        sys.modules = modules
        rename(dst2, dst1)
        chdir(current_path)

        for name, value in locals_.items():
            locals()[name] = value

        for name, value in globals_.items():
            globals()[name] = value

    if error:
        raise error


disable_logs()
import_without_package()

import WebScripts

sys.argv = ["WebScripts", "--debug"]
WebScripts.main()
sys.argv = argv
