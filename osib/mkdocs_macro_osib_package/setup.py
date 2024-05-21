import setuptools

with open("../README.md", "r") as fh:
    long_description    = fh.read()

setuptools.setup(
    name                ="mkdocs_macro_osib",
    version             ="0.9.0",
    author              ="Torsten Gigler as member of the OWASP Top 10 Team 2021",
    description         ="MkDocs-Macro to use and extend the Open Security Information Base (OSIB) to provide, manage and use links between it-security documents, e.g. standards, best practices e.g. projects",
    long_description    =long_description,
    long_description_content_type="text/markdown",
    url                 ="https://github.com/sslHello/OSIB-Test",
    packages            =["mkdocs_macro_osib"],
    licence             ="GPLv2: GPL - The GNU General Public License, version 2 as specified in: http://www.gnu.org/licenses/gpl-2.0"
)
