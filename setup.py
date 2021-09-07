from setuptools import setup, find_packages
import WebScripts as package

setup(
    name=package.__name__,
    version=package.__version__,
    packages=find_packages(include=[package.__name__]),
    author=package.__author__,
    author_email=package.__author_email__,
    maintainer=package.__maintainer__,
    maintainer_email=package.__maintainer_email__,
    description=package.__description__,
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url=package.__url__,
    project_urls={
        "Documentation": "https://github.com/mauricelambert/WebScripts/wiki",
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Server",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9",
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
)
