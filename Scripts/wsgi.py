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
"""

__version__ = "1.0.2"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = (
    "This tool runs CLI scripts and displays output in a Web Interface."
)
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

print(copyright)

from os.path import join, dirname
from typing import List
import atexit

activator = join(dirname(__file__), "activate_this.py")

with open(activator) as f:
    exec(f.read(), {"__file__": activator})  # nosec # nosemgrep

from WebScripts.WebScripts import (
    Server,
    configure_logs_system,
    send_mail,
    hardening,
    Logs,
    logger_debug,
    logger_info,
    logger_warning,
    prepare_server,
)


class Paths:

    """
    This class define configuration files.
    """

    def __init__(self, config_cfg: List[str], config_json: List[str]):
        self.config_cfg = config_cfg
        self.config_json = config_json

paths = Paths([], [])

server, _ = prepare_server()

logger_debug("Trying to send email notification...")
send_mail(
    server.configuration, f"Server is up on http://{server.interface}:{server.port}/."
)

logger_debug("Configure email notification on server exit...")
atexit.register(
    send_mail,
    server.configuration,
    f"Server is down on http://{server.interface}:{server.port}/.",
)

logger_info("WebScripts server hardening audit...")
hardening(server)

logger_warning("Starting server...")
application = server.app
