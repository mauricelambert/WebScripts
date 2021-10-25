#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os import path, chdir, name
from typing import List
import logging
import atexit

chdir(path.join(path.dirname(__file__), ".."))

activator = r"Scripts\activate_this.py" if name == "nt" else "bin/activate_this.py"
with open(activator) as f:
    exec(f.read(), {"__file__": activator}) # nosec # nosemgrep

from WebScripts.WebScripts import (
    server_path,
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

    """This class define configuration files."""

    def __init__(self, config_cfg: List[str], config_json: List[str]):
        self.config_cfg = config_cfg
        self.config_json = config_json


configure_logs_system()
paths = Paths([], [])

configuration = Configuration()
for config in get_server_config(paths):
    configuration = add_configuration(configuration, config)

logs_configuration(configuration)

configuration.set_defaults()
configuration.check_required()
configuration.get_unexpecteds()
configuration.build_types()

server = Server(configuration)

send_mail(configuration, f"Server is up on http://{server.interface}:{server.port}/.")

atexit.register(
    send_mail,
    configuration,
    f"Server is down on http://{server.interface}:{server.port}/.",
)

hardening(server, Logs, send_mail)
application = server.app
