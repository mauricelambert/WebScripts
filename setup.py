#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This tools run scripts and display the result in a Web Interface.
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

"""This tools run scripts and display the result in a Web Interface."""

__version__ = "2.2.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = (
    """This tools run scripts and display the result in a Web Interface."""
)
__license__ = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/WebScripts"

copyright = """
WebScripts  Copyright (C) 2021  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
license = __license__
__copyright__ = copyright

print(copyright)

from importlib.machinery import SourceFileLoader
from setuptools.command.install import install

# from setuptools.command.develop import develop
from setuptools import setup, find_packages
from getpass import getuser
from typing import Dict
from os import path

import WebScripts as package
import importlib.util
import logging
import json
import sys
import os


arguments = [
    (
        "json-only",
        "j",
        "Delete the file named server.ini, to keep only the JSON"
        " configuration.",
    ),
    (
        "admin-password=",
        "p",
        'Administrator password for the WebScripts account "Admin"'
        " (the default account).",
    ),
    (
        "owner=",
        "o",
        "The owner of WebScripts Server (set the owner of files on "
        "UNIX systems if you are installing with privileges).",
    ),
    ("no-hardening", "n", "Do not harden during installation."),
]


class PostInstallScript(install):

    """This class installs and hardens the WebScripts project."""

    logging.basicConfig(
        filemode="w",
        filename="install.log",
        format="%(levelname)s\t::\t%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.DEBUG,
        force=True,
    )
    logging.debug("Logging is configured")

    logging.debug("Add custom arguments")
    user_options = install.user_options + arguments

    logging.debug("System detection")
    is_windows = os.name == "nt"

    if is_windows:
        logging.warning("Permissions can not be change on Windows system.")
        logging.warning("Owner can not be change on Windows system.")

    def initialize_options(self):
        super(self.__class__, self).initialize_options()

        logging.debug("Initialize argument variables")
        self.json_only = False
        self.no_hardening = False
        self.admin_password = None
        self.owner = None

        logging.debug("Initialize custom properties")
        self.is_admin = None
        self.owner_property = None
        self.json_config_files = []
        self.ini_config_files = []
        self.py_scripts_files = []

    def linux_files_permissions(self, filename: str) -> None:

        """This function changes the owner and permissions on
        UNIX system files if you perform the installation
        with privileges."""

        if self.is_windows:
            return

        if self.is_admin is None:
            self.is_admin = os.getuid() == 0

        if not self.is_admin:
            logging.warning(
                "Permissions can not be change without privileges."
            )
            logging.warning("Owner can not be change without privileges.")

            return None

        if self.owner_property is None:
            from pwd import getpwnam

            logging.debug("Owner detection")
            owner = self.owner or getuser()
            logging.info(f"The owner will be {owner}")

            self.owner_property = getpwnam(owner)
            logging.info(f"UID will be {self.owner_property.pw_uid}")
            logging.info(f"GID will be {self.owner_property.pw_gid}")

        logging.debug(f"Change the owner of {filename}")
        os.chown(
            filename, self.owner_property.pw_uid, self.owner_property.pw_gid
        )

        logging.debug(f"Change the permissions of {filename}")

        file = path.split(filename)[1]
        extension = path.splitext(filename)[1]
        directory = path.dirname(filename)

        if file == "id" or extension == ".csv":
            os.chmod(filename, 0o600)
        else:
            os.chmod(filename, 0o400)

        if file == "wsgi.py" or extension in (".json", ".ini"):
            # logging.debug(
            #     f"Add the execution permission for the owner on {filename}"
            # )
            # os.chmod(filename, 0o400)

            dir_ = path.dirname(filename)
            logging.debug(
                f'Change permissions and owner on directory "{dir_}"'
            )
            os.chmod(dir_, 0o755)  # nosec
            os.chown(dir_, 0, 0)
        elif file == "WebScripts":
            logging.debug(
                f"Add the execution permissions for the owner on {filename}"
            )
            os.chmod(filename, 0o700)
        elif directory.endswith("data/uploads"):
            logging.debug("Change owner for uploads directory")
            os.chown(
                directory,
                self.owner_property.pw_uid,
                self.owner_property.pw_gid,
            )

    def add_absolute_paths_in_configuration(self) -> None:

        """This function adds absolute paths on configurations."""

        launcher = sys.executable
        for filename in self.json_config_files:

            logging.debug(f"Open and loads {filename}")
            with open(filename) as file:
                configurations: Dict[str, dict] = json.load(file)

            scripts = configurations.get("scripts")

            if scripts is None:
                logging.info("Configure specific configuration file")
                script = configurations.get("script")

                if script is not None:
                    logging.debug("Add the launcher")
                    script["launcher"] = launcher

                    script_name, _ = path.splitext(path.basename(filename))
                    logging.info(f"Configure script named: {script_name}")
                    for py_filename in self.py_scripts_files:
                        if py_filename.endswith(f"{script_name}.py"):
                            logging.debug("Add the script absolute path.")
                            script["path"] = py_filename

                PostInstallScript.save_scripts_configurations(
                    filename, configurations
                )
                continue

            for name, section_name in scripts.items():
                logging.info(f"Configure {name}")
                section = configurations.get(section_name)
                specific_config_file = section.get("configuration_file")

                if specific_config_file:
                    specific_config_file = path.basename(specific_config_file)
                    for config_file in self.json_config_files:
                        if config_file.endswith(specific_config_file):
                            section["configuration_file"] = config_file
                    continue

                logging.debug("Add launcher")
                section["launcher"] = launcher

                for py_filename in self.py_scripts_files:
                    if py_filename.endswith(name):
                        logging.debug("Add the script absolute path.")
                        section["path"] = py_filename

            server = configurations.get("server")

            if server is not None:
                path_ = [path.dirname(filename), "..", "modules"]

                if self.is_windows:
                    path_.insert(1, "..")

                server["modules_path"] = path.abspath(path.join(*path_))

            PostInstallScript.save_scripts_configurations(
                filename, configurations
            )

    @staticmethod
    def save_scripts_configurations(
        filename: str, configurations: Dict[str, dict]
    ) -> None:

        """This function save configuration."""

        logging.debug(f"Save new/secure configurations in {filename}")
        with open(filename, "w") as file:
            json.dump(configurations, file, indent=4)

    def remove_configuration_files(self) -> None:

        """This function removes unnecessary configuration files."""

        sub_path = path.join("config", "nt")

        if not self.no_hardening or self.json_only:
            logging.info("Remove server.ini files")
            ini_config_files = self.ini_config_files.copy()

            for file in ini_config_files:
                os.remove(file)
                self.ini_config_files.remove(file)

        if self.no_hardening:
            return

        logging.debug("Research unused configuration files")
        if PostInstallScript.is_windows:
            unused_configurations = [
                f for f in self.json_config_files if sub_path not in f
            ]
        else:
            unused_configurations = [
                f for f in self.json_config_files if sub_path in f
            ]

        logging.info("Remove unused configuration files")
        for file in unused_configurations:
            logging.debug(f"Remove {file}.")
            os.remove(file)
            self.json_config_files.remove(file)

    def change_admin_password(self) -> None:

        """
        This function change the administrator
        password (default account named Admin).
        """

        if not self.admin_password:
            logging.warning(
                "The default administrator password is not changed (argument:"
                " --admin-password/-p is not used)."
            )
            return

        logging.debug("Import manage_defaults_databases (account manager)")
        module_name = "manage_defaults_databases"
        for filename in self.py_scripts_files:
            if filename.endswith(f"{module_name}.py"):
                loader = SourceFileLoader(module_name, filename)
                break

        spec = importlib.util.spec_from_loader(module_name, loader)
        manage_defaults_databases = importlib.util.module_from_spec(spec)
        loader.exec_module(manage_defaults_databases)

        manage_defaults_databases.change_user_password(
            "2", self.admin_password
        )
        logging.info("Administrator is changed.")

    def run_custom_install(self) -> None:

        """This function launch custom install."""

        logging.basicConfig(
            filename="install.log",
            format="%(levelname)s\t::\t%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            level=logging.DEBUG,
            force=True,
        )
        logging.debug("Logging is configured")

        for filename in self.get_outputs():
            if not self.no_hardening:
                PostInstallScript.linux_files_permissions(self, filename)

            extension = path.splitext(filename)[1]

            if extension == ".json":
                self.json_config_files.append(filename)

            elif extension == ".py":
                self.py_scripts_files.append(filename)

            elif path.split(filename)[1] == "server.ini":
                self.ini_config_files.append(filename)

        PostInstallScript.remove_configuration_files(self)
        if not self.no_hardening:
            PostInstallScript.add_absolute_paths_in_configuration(self)

        PostInstallScript.change_admin_password(self)

    def run(self):
        return_value = super(self.__class__, self).run()
        PostInstallScript.run_custom_install(self)
        return return_value


# class PostDevelopScript(develop):
#    user_options = develop.user_options + arguments
#    is_windows = PostInstallScript.is_windows
#    run = PostInstallScript.run

setup(
    name=package.__name__,
    version=package.__version__,
    packages=find_packages(include=[package.__name__]),
    scripts=[
        path.join("Scripts", "wsgi.py"),
        path.join("Scripts", "activate_this.py"),
    ],
    author=package.__author__,
    author_email=package.__author_email__,
    maintainer=package.__maintainer__,
    maintainer_email=package.__maintainer_email__,
    description=package.__description__,
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url=package.__url__,
    project_urls={
        "Documentation": "https://webscripts.readthedocs.io/en/latest/",
        "Wiki": "https://github.com/mauricelambert/WebScripts/wiki",
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Server",
        "Topic :: System :: Systems Administration",
        "Topic :: Communications :: File Sharing",
        "Topic :: Utilities",
        "Topic :: Security",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    keywords=[
        "Server",
        "Web",
        "Scripts",
        "SOC",
        "Administration",
        "DevOps",
        "WebScripts",
    ],
    platforms=["Windows", "Linux", "MacOS"],
    license=package.__license__,
    entry_points={
        "console_scripts": ["WebScripts = WebScripts:main"],
    },
    python_requires=">=3.9",
    cmdclass={
        # 'develop': PostDevelopScript,
        "install": PostInstallScript,
    },
)
