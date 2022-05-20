#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List
from os import name
import atexit

activator = (
    r"Scripts\activate_this.py" if name == "nt" else "bin/activate_this.py"
)
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
    default_configuration,
)


class Paths:

    """
    This class define configuration files.
    """

    def __init__(self, config_cfg: List[str], config_json: List[str]):
        self.config_cfg = config_cfg
        self.config_json = config_json


configure_logs_system()

paths = Paths([], [])

configuration = default_configuration()

logger_debug("Build server with configurations...")
server = Server(configuration)

logger_debug("Trying to send email notification...")
send_mail(
    configuration, f"Server is up on http://{server.interface}:{server.port}/."
)

logger_debug("Configure email notification on server exit...")
atexit.register(
    send_mail,
    configuration,
    f"Server is down on http://{server.interface}:{server.port}/.",
)

logger_info("Check hardening of the WebScripts server...")
hardening(server, Logs, send_mail)

logger_warning("Starting server...")
application = server.app
