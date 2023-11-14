# Filename: osib_macro.py
#!##################################################################################################################################################
#!#                                  MkDocs-Macro to use and extend the Open Security Information Base (OSIB)
#!#                                                         Version: 2023-06-10
#!# ------------------------------------------------------------------------------------------------------------------------------------------------
#!#                            THIS Software is in BETA state, please give us feed back via the github repository
#!#                                   Project Page: https://owasp.org/www-project-open-security-information-base
#!#                            Software Repository: https://github.com/OWASP/OSIB
#!#
#!##################################################################################################################################################$
#!#
#!# This MkDocs MACRO has been developed by the OWASP-Top 10 Project in 2021.
#!# It provides a central management of links in MkDocs documents. This includes the versioning of links inside a project,
#!# standard or a group of documents and to external sources. By exporting the update OSIB structure in a YAML file all efforts
#!# done by one volunteering group can be used by any other project, standard or document that refers to the same links.
#!# This reduces or even avoids a lot of unnecessary, redundant work to track and to update links.
#!# The OSIB tree and this macro are capable to handle multilingual versions for links.
#!#
#!# ------------------------------------------------------------------------------------------------------------------------------------------------
#!#
#!# This Python program provides two MkDocs macros to use with markdown:
#!# - osib_anchor:  Adds an OSIB anchor and an object to an osib YAML structure
#!#         Input:  osib_anchor(osib=osib.<organization>.<project|standard>.<version(without dots '.')>.<internal structure>, create_organization=False
#!#                             source_id=<id inside the source>, lang=<lang>, source=<url_i18n>, name=<name_i18n>,
#!#                             parent=<osib-id>, predecessor=<osib-id>, splitted_from=<osib.id>, merged_from=<osib-id>
#!#                             cre=<osib-id>, aliases=[<list of aliases>, ...])
#!#         Output: '<a id="<osib>"></a>' (HTTP-anchor), and updates in the OSIB YAML tree
#!#
#!# - osib_link:    Get links from a osib YAML tree, optionally find successors and add linking information bidirectionally
#!#                 to the OSIB YAML tree
#!#       Input:    osib_link  (link=osib.<organization>.<project|standard>.<version(without dots '.')>.<internal structure>, create_organization=False
#!#                             doc=<osib>, type=<reference|predecessor|successor|merged_from|ispiltted_from|...>,
#!#                             osib=<osib>, reviewed=<datestamp(YYYYMMDD)>, status=<active|draft|...>)
#!#       Output:   markdown link format '["<text>|<prefix><doc_osib><doc_suffix><osib_names>"](<html_link>)<speparator> ..') and/or successor/s
#!#
#!# ====> Exports optionally to an OSIB YAML file with all added information to be uses by other versions, projects, standards and
#!#       standard linking projects like OWASP Common Requirement Enumeration (https://github.com/OWASP/common-requirement-enumeration, opencre.org)
#!#
#!# ------------------------------------------------------------------------------------------------------------------------------------------------
#!#
#!# Requirements:
#!# - mkdocs:               pip install mkdocs               (https://www.mkdocs.org)
#!# - mkdocs-macros-plugin: pip install mkdocs-macros-plugin (https://mkdocs-macros-plugin.readthedocs.io/en/latest/)
#!# - dacite:               pip install dacite               (https://github.com/konradhalas/dacite)
#!# - mkdocs-macro-osib:    cd mkdocs-macro-osib_package
#!#                         pip install .
#!#
#!# To use the macros add in 'mkdocs.yml' (if you use the plugin 'i18n' add this macro after it):
#!# plugins:
#!#   - macros:                                                         # needs to be the last plugin to export the final osib-YAML file for all languages
#!#      module_name: 'osib_macro'
#!#      include_dir: include
#!#      verbose: true                                                  # debug
#!#
#!# # Optionally you can define variables in the 'extra' section:
#!# extra:
#!#     osib:
#!#      document:     <osib-id>                    # e.g. osib.owasp.top10
#!#      version:      <version-no, no dots '.'>    # e.g. 4-0, 2021-1-0
#!#      categories:   [document, awareness]        # list of all default categories
#!#      default_lang: en
#!#      yaml_file:    include/osib.yml
#!#      export_dir:   export
#!#      latest:       2                            # 2: add the latest version(s), if successor(s) exist, log an info
#!#      debug:        0                            # debug level (0-4)
#!#      cre:          osib.owasp.cre.1-0
#!#      successor_texts:
#!#        en:         successor
#!#        de:         Nachfolger
#!#      split_to_texts:
#!#        en:         split to
#!#        de:         Aufgeteilt in
#!#
#!# ------------------------------------------------------------------------------------------------------------------------------------------------
#!# This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties
#!# of merchantability, fitness for a particular purpose. In no event shall the copyright holders or authors be liable for any claim,
#!# damages or other liability. This software is distributed in the hope that it will be useful.
#!#
#!# (C) OWASP/The Top10-Team, 2021
#!#
#!# This  software is licensed under GPLv2.
#!# GPL - The GNU General Public License, version 2 as specified in:  http://www.gnu.org/licenses/gpl-2.0
#!#
#!# Permits anyone the right to use and modify the software without limitations as long as proper credits are given and the original and modified source
#!# code are included. Requires that the final product, software derivate from the original source or any software utilizing a GPL component, such as
#!# this, is also licensed under the same GPL license.
#!#
#!##################################################################################################################################################

from mkdocs_macro_osib import define_env, on_post_build
#provides MkDocs macros 'osib_anchor' and 'osib_link'

