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

This file hardens the WebScripts installation and configuration.
"""

__version__ = "0.0.8"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This tool runs CLI scripts and displays output in a Web Interface.

This file hardens the WebScripts installation and configuration.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021, 2022, 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = ["Hardening"]

print(copyright)

from os import name

from os import (
    getcwd,
    chmod,
    remove,
    mkdir,
    makedirs,
    environ,
    listdir,
)
from os.path import (
    isdir,
    dirname,
    split,
    splitext,
    join,
    abspath,
    basename,
    exists,
)
from importlib.util import spec_from_loader, module_from_spec
from logging import FileHandler, Formatter, getLogger, Logger
from importlib.machinery import SourceFileLoader
from argparse import ArgumentParser, Namespace
from sys import _getframe, executable
from collections.abc import Callable
from typing import Tuple, List, Dict
from getpass import getuser
from json import load, dump
from shutil import copytree
from glob import iglob


if name != "nt":
    from os import chown, getuid


def prepare(arguments: Namespace) -> Tuple[str, List[str]]:
    """
    This function prepares WebScripts to be hardened.
    """

    path = dirname(__file__)

    files = []

    for directory in (arguments.directory, path):
        hardening_path = join(directory, "hardening")
        log_path = join(directory, "logs")

        if not isdir(hardening_path):
            mkdir(hardening_path)
        if not isdir(log_path):
            mkdir(log_path)

        for filename in (
            "logs_checks.json",
            "uploads_file_integrity.json",
            "webscripts_file_integrity.json",
            "audit.html",
            "audit.txt",
            "audit.json",
        ):
            filename = join(hardening_path, filename)
            files.append(filename)
            if not exists(filename):
                with open(filename, "w") as file:
                    file.write("{}")

    return path, hardening_path, log_path, files


def get_custom_logger(path: str, name: str = None) -> Logger:
    """
    This function creates a custom logger.
    """

    name = name or _getframe().f_code.co_filename
    logger = getLogger(name)
    logger.propagate = False

    if not logger.handlers:
        formatter = Formatter(
            fmt=(
                "%(asctime)s%(levelname)-9s(%(levelno)s) "
                "{%(name)s - %(filename)s:%(lineno)d} %(message)s"
            ),
            datefmt="[%Y-%m-%d %H:%M:%S] ",
        )
        file = FileHandler(join(path, name + ".log"))
        file.setFormatter(formatter)

        logger.addHandler(file)
        logger.setLevel(1)

    return logger


parser = ArgumentParser(
    description="This script hardens the WebScripts installation."
)
parser.add_argument(
    "--admin-password",
    "-p",
    "--password",
    required=True,
    help="The new WebScripts administrator password.",
)
# parser.add_argument(
#     "--json-only",
#     "-j",
#     default=True,
#     action="store_false",
#     help="Keep only JSON configurations."
# )
parser.add_argument(
    "--owner",
    "-o",
    required=True,
    help=(
        "The user name that launches the WebScripts"
        " service (a specific user for that service only).",
    ),
)
parser.add_argument(
    "--directory",
    "-d",
    required=True,
    help="The directory where the WebScripts service will be launched.",
)
arguments = parser.parse_args()

path, hardening_path, log_path, files = prepare(arguments)
logger: Logger = get_custom_logger(hardening_path, "hardening")
logger_debug: Callable = logger.debug
logger_info: Callable = logger.info
logger_warning: Callable = logger.warning
logger_error: Callable = logger.error
logger_critical: Callable = logger.critical
logger_log: Callable = logger.log


class Hardening:

    """
    This class hardens WebScripts.
    """

    def __init__(
        self,
        admin_password: str = None,
        json_only: bool = True,
        owner: str = None,
        directory: str = None,
    ):
        self.admin_password = admin_password
        self.json_only = json_only
        self.owner = owner or getuser()
        self.directory = directory or getcwd()
        is_windows = self.is_windows = name == "nt"

        self.is_admin = None if is_windows else (getuid() == 0)
        self.json_config_files = []
        self.ini_config_files = []
        self.py_scripts_files = []
        self.owner_property = None
        self.csv_files = []

        if is_windows:
            logger_warning("Permissions can not be change on Windows system.")
            logger_warning("Owner can not be change on Windows system.")
        else:
            from pwd import getpwnam

            logger_info(f"The owner will be {owner}")

            self.owner_property = getpwnam(owner)
            logger_info(
                f"UID will be {self.owner_property.pw_uid}, "
                f"GID will be {self.owner_property.pw_gid}"
            )

        if not self.is_admin:
            logger_warning("Permissions can not be change without privileges.")
            logger_warning("Owner can not be change without privileges.")

    def get_configurations(
        self, filename: str, script_name: str = None
    ) -> None:
        """
        This method gets scripts from configurations file.
        """

        logger_debug(f"Open and loads {filename!r}")
        with open(filename) as file:
            configurations: Dict[str, dict] = load(file)

        scripts = configurations.get("scripts")
        has_no_script = scripts is None

        if has_no_script and script_name is not None:
            logger_debug("Check for specific configuration file")
            script = configurations.get("script")

            if script is not None:
                logger_info(
                    "Specific configuration file found"
                    f" for {script_name!r} (filename)"
                )
                self.harden_script(script, script_name)

        elif not has_no_script:
            for name, section_name in scripts.items():
                self.harden_script(configurations[section_name], name)

        server = configurations.get("server")
        if server is not None:
            self.harden_server(server, dirname(filename))

        Hardening.save_scripts_configurations(filename, configurations)

    def get_files_from_glob_path(
        self, path: List[str], globsyntax: List[str]
    ) -> List[str]:
        """
        This method returns all files (with absolute path) matching
        a list of glob syntax.
        """

        return [abspath(x) for g in globsyntax for x in iglob(join(*path, g))]

    def harden_server(self, section: dict, directory: str) -> None:
        """
        This method hardens server configuration.
        """

        logger_info("Hardens the WebScripts server configuration...")
        path_ = [directory, ".."]

        if self.is_windows:
            path_.insert(1, "..")

        section["modules_path"] = abspath(join(*path_, "modules"))
        section["data_dir"] = abspath(join(self.directory, "data"))
        section["json_scripts_config"] = self.get_files_from_glob_path(
            path_, section["json_scripts_config"]
        )
        section["ini_scripts_config"] = self.get_files_from_glob_path(
            path_, section["ini_scripts_config"]
        )
        section["scripts_path"] = self.get_files_from_glob_path(
            path_, section["scripts_path"]
        )
        section["js_path"] = self.get_files_from_glob_path(
            path_, section["js_path"]
        )
        section["statics_path"] = self.get_files_from_glob_path(
            path_, section["statics_path"]
        )

    def harden_script(self, section: dict, filename: str) -> None:
        """
        This method hardens script configuration.
        """

        logger_info("Hardens script " + repr(filename))
        logger_debug("Add the launcher")
        section["launcher"] = executable
        specific_config_file = section.get("configuration_file")

        if specific_config_file:
            specific_config_file = basename(specific_config_file)

            script_name, _ = splitext(basename(filename))
            logger_info(f"Configure script named: {script_name}")
            for config_file in self.json_config_files:
                if config_file.endswith(specific_config_file):
                    section["configuration_file"] = config_file
                    self.get_configurations(config_file, filename)
                    break

        for py_filename in self.py_scripts_files:
            if py_filename.endswith(filename):
                logger_debug("Add the script absolute path.")
                section["path"] = py_filename
                break

    def linux_hardening_file_permissions(self) -> None:
        """
        This method changes files permissions for hardening file.
        """

        pw_uid = self.owner_property.pw_uid
        pw_gid = self.owner_property.pw_gid
        directory = self.directory

        for file in files:
            chmod(file, 0o600)
            chown(file, pw_uid, pw_gid)

        logger_warning(f"Change permissions and owner of {directory}")
        chmod(directory, 0o755)  # nosec
        chown(directory, 0, 0)

        chmod(hardening_path, 0o755)  # nosec
        chown(hardening_path, 0, 0)

        chmod(log_path, 0o700)  # nosec
        chown(log_path, pw_uid, pw_gid)

        hardening = join(directory, "hardening")
        chmod(hardening, 0o755)  # nosec
        chown(hardening, 0, 0)

        logs = join(directory, "logs")
        chmod(logs, 0o700)  # nosec
        chown(logs, pw_uid, pw_gid)

    def linux_file_permissions(self, filename: str) -> None:
        """
        This method changes files permissions on Linux.
        """

        owner_property = self.owner_property
        owner = self.owner

        filename = abspath(filename)
        file = split(filename)[1]
        extension = splitext(filename)[1]
        directory = dirname(filename)

        change_owner_directory: bool = True
        change_permission_directory: bool = True

        logger_debug(f"Change the permissions of {filename}")

        if file == "WebScripts":
            logger_debug(
                f"Add the execution permissions for the owner on {filename}"
            )
            chmod(filename, 0o500)

        elif directory.endswith("data/uploads") or directory.endswith(
            "WebScripts/doc"
        ):
            logger_debug(f"Change owner for {directory} directory")
            chmod(directory, 0o700)
            chown(
                directory,
                owner_property.pw_uid,
                owner_property.pw_gid,
            )
            change_owner_directory = False
            change_permission_directory = False

            if directory.endswith("WebScripts/doc"):
                directory = directory[:-3] + "logs"
                makedirs(directory, exist_ok=True)
                chown(
                    directory,
                    owner_property.pw_uid,
                    owner_property.pw_gid,
                )
                chmod(directory, 0o700)
        elif file == "id" or extension == ".csv":
            chmod(filename, 0o600)
        else:
            chmod(filename, 0o400)

        logger_debug(f"Change the owner of {filename}")
        chown(filename, owner_property.pw_uid, owner_property.pw_gid)

        logger_debug(
            f"Change permissions and owner on directory {directory!r}"
        )
        if change_permission_directory:
            chmod(directory, 0o755)  # nosec

        if change_owner_directory:
            chown(directory, 0, 0)

    @staticmethod
    def save_scripts_configurations(
        filename: str, configurations: Dict[str, dict]
    ) -> None:
        """
        This function saves a configuration file.json_only
        """

        logger_warning("Save new/secure configurations in " + filename)
        with open(filename, "w") as file:
            dump(configurations, file, indent=4)

    def remove_configuration_files(self) -> None:
        """
        This function removes unnecessary configuration files.
        """

        sub_path = join("config", "nt")

        if self.json_only:
            logger_info("Remove server.ini files")
            ini_config_files = self.ini_config_files.copy()

            for file in ini_config_files:
                logger_info("Remove INI configuration file " + repr(file))
                remove(file)
                self.ini_config_files.remove(file)

        logger_debug("Research unused configuration files")
        if self.is_windows:
            unused_configurations = [
                f for f in self.json_config_files if sub_path not in f
            ]
        else:
            unused_configurations = [
                f for f in self.json_config_files if sub_path in f
            ]

        logger_info("Remove unused configuration files")
        for file in unused_configurations:
            logger_debug(f"Remove {file}.")
            remove(file)
            self.json_config_files.remove(file)

    def change_admin_password(self) -> None:
        """
        This function change the administrator
        password (default account named Admin).
        """

        if not self.admin_password:
            logger_warning(
                "The default administrator password is not changed (argument:"
                " --admin-password/-p is not used)."
            )
            return None

        logger_debug("Import manage_defaults_databases (account manager)")
        module_name = "manage_defaults_databases"
        file_name = module_name + ".py"

        for filename in self.py_scripts_files:
            if filename.endswith(file_name):
                logger_info(
                    "Module to change Admin password found in "
                    + repr(filename)
                )
                loader = SourceFileLoader(module_name, filename)
                break

        for filename in self.csv_files:
            if filename.endswith("users.csv"):
                logger_info("Users CSV database found in " + repr(filename))
                environ["WEBSCRIPTS_DATA_PATH"] = split(filename)[0]
                break
        # Environment variable WEBSCRIPTS_DATA_PATH is used
        # in manage_defaults_databases module

        try:
            spec = spec_from_loader(module_name, loader)
        except UnboundLocalError:
            logger_critical(
                "manage_defaults_databases module not found,"
                " Admin password is not changed ! Installation"
                " files have been modified !"
            )
            return None
        manage_defaults_databases = module_from_spec(spec)
        loader.exec_module(manage_defaults_databases)

        manage_defaults_databases.change_user_password(
            "2", self.admin_password
        )
        logger_info("Administrator is changed.")

    def add_data_directory(self) -> None:
        """
        This method adds a data directory
        based on the WebScripts data directory.
        """

        new_data_path = join(self.directory, "data")

        if not isdir(new_data_path):
            copytree(join(path, "data"), new_data_path)

        for file in iglob(join(new_data_path, "**"), recursive=True):
            chown(file, self.owner_property.pw_uid, self.owner_property.pw_gid)

    def hardening(self) -> None:
        """
        This function starts hardening.
        """

        logger_debug("Logging is configured")
        linux_hardening: bool = not self.is_windows and self.is_admin

        for filename in iglob(join(path, "**"), recursive=True):
            if linux_hardening:
                self.linux_file_permissions(filename)

            extension = splitext(filename)[1]

            if extension == ".json":
                logger_debug("Add JSON file " + repr(filename))
                self.json_config_files.append(filename)

            elif extension == ".py":
                logger_debug("Add python file " + repr(filename))
                self.py_scripts_files.append(filename)

            elif split(filename)[1] == "server.ini":
                logger_debug("Add INI file " + repr(filename))
                self.ini_config_files.append(filename)

            elif extension == ".csv":
                logger_debug("Add CSV file " + repr(filename))
                self.csv_files.append(filename)

        executable_path = dirname(executable)
        for filename in listdir(executable_path):
            if filename == "wsgi.py" or filename == "activate_this.py":
                filename = join(executable_path, filename)
                if linux_hardening:
                    self.linux_file_permissions(filename)
                self.py_scripts_files.append(filename)

        for config_file in self.json_config_files:
            self.get_configurations(config_file)

        self.remove_configuration_files()
        self.change_admin_password()
        if linux_hardening:
            self.linux_hardening_file_permissions()
            self.add_data_directory()


Hardening(**arguments.__dict__).hardening()
