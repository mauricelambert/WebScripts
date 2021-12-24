#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from collections.abc import Callable
from os.path import join, dirname
from os import chdir, name
from typing import List
import atexit

chdir(join(dirname(__file__), ".."))

activator = (
    r"Scripts\activate_this.py" if name == "nt" else "bin/activate_this.py"
)
with open(activator) as f:
    exec(f.read(), {"__file__": activator})  # nosec # nosemgrep

from WebScripts.WebScripts import (
    Configuration,
    get_server_config,
    add_configuration,
    logs_configuration,
    Server,
    configure_logs_system,
    send_mail,
    hardening,
    Logs,
)


class Paths:

    """
    This class define configuration files.
    """

    def __init__(self, config_cfg: List[str], config_json: List[str]):
        self.config_cfg = config_cfg
        self.config_json = config_json


configure_logs_system()

logger_debug: Callable = Logs.debug
logger_info: Callable = Logs.info
logger_warning: Callable = Logs.warning
paths = Paths([], [])

logger_debug("Load configurations...")
configuration = Configuration()
for config in get_server_config(paths):
    configuration = add_configuration(configuration, config)

logs_configuration(configuration)

logger_debug("Check and type configurations...")
configuration.set_defaults()
configuration.check_required()
configuration.get_unexpecteds()
configuration.build_types()

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
