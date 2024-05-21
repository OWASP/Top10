# Filename: mkdocs_macro_osib.py
#!##################################################################################################################################################
#!#                                  MkDocs-Macro to use and extend the Open Security Information Base (OSIB)
#!#                                                         Version: 2021-12-05
#!# ------------------------------------------------------------------------------------------------------------------------------------------------
#!#                            THIS Software is in BETA state, please give us feed back via the github repository
#!#                                                   https://github.com/sslHello/OSIB-Test
#!# ------------------------------------------------------------------------------------------------------------------------------------------------
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
#!#                             parent=<osib-id>, predecessor=<osib-id>, split_from=<osib-id>, merged_from=[<list of osib-ids>, ... ],
#!#                             cre=<osib-id>, aliases=[<list of aliases>, ...])
#!#         Output: '<a id="<osib>"></a>' (HTTP-anchor), and updates in the OSIB YAML tree
#!#
#!# - osib_link:    Get links from a osib YAML tree, optionally find successors and add linking information bidirectionally
#!#                 to the OSIB YAML tree
#!#       Input:    osib_link  (link=osib.<organization>.<project|standard>.<version(without dots '.')>.<internal structure>, create_organization=False
#!#                             doc=<osib>, type=<reference|predecessor|successor|merged_from|split_from|...>,
#!#                             osib=<osib>, reviewed=<datestamp(YYYYMMDD)>, status=<active|draft|...>)
#!#       Output:   markdown link format '["<text>|<prefix><doc_osib><doc_suffix><osib_names>"](<html_link>)<speparator> ..') and/or successor/s
#!#
#!# ====> Exports optionally to an OSIB YAML file with all added information to be uses by other versions, projects, standards and
#!#       standard linking projects like OWASP Common Requirement Enumeration (https://github.com/OWASP/common-requirement-enumeration, opencre.org)
#!#
#!# ------------------------------------------------------------------------------------------------------------------------------------------------
#!#
#!# Requirements:
#!# - mkdocs:               pip install mkdocs               (https://mkdocs.org)
#!# - mkdocs-macros-plugin: pip install mkdocs-macros-plugin (https://mkdocs-macros-plugin.readthedocs.io/en/latest/)
#!# - dacite:               pip install dacite               (https://github.com/konradhalas/dacite)
#!#
#!# Installation:
#!# Actually 'manual installation' only:
#!#    cd <your path>/mkdocs-macro-osib_package
#!#    pip install .
#!# verify if osib is in your pip list
#!#    pip list | grep osib
#!#
#!# Developers Installation
#!#    cd <your path>/mkdocs-macro-osib_package
#!#    pip install -e .
#!# verify if osib is in your pip list
#!#    pip list | grep osib
#!#
#!$ Copy or edit 'osib_macro.py' to the root folder of your mkdocs document
#!#    from mkdocs-macro-osib import define_env, on_post_build
#!#    #provides MkDocs macros 'osib_anchor' and 'osib_link'
#
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
#!#      debug:        2                            # debug level (0-4)
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

import os
import warnings
import logging
import re
from typing import Any, Dict, List, Union, NewType
from datetime import datetime
from dataclasses import dataclass, field, asdict
from dacite import from_dict, Config, ForwardReferenceError, UnexpectedDataError, StrictUnionMatchError
import yaml


yaml_file           = "include/osib.yml"                            # Default import yaml file
export_dir          = "export"                                      # Default Export dirctory
debug               = 2                                             # debug level 0 ... 4
default_lang        = "en"                                          # default language is 'en'
categories_default  = []                                            # no categories by default
latest_default      = 2
successor_texts     = {
                        "en":           "successor"                 # English text for successors
                      }
split_to_texts      = {
                        "en":           "split to"                  # English text for split successors
                      }
osib_yaml           = None
added_yaml_data     = 0
osib_warnings       = 0
now                 = datetime.now()
datestamp           = int(now.strftime("%Y%m%d"))                   # get datestamp as numeric value
reverse_types_dict  = {                                             # list of reverse link types
                        "parent":       "child",
                        "child":        "parent",
                        "peer":         "peer",
                        "predecessor":  "successor",
                        "merged_from":  "merged_to",
                        "split_from":   "split_to",
                        "successor":    "predecessor",
                        "merged_to":    "merged_from",
                        "split_to":     "split_to",
                        "reference":    "reference"
                      }
types_list          = list(reverse_types_dict.keys())               # define a primary order for link lists

logger              = logging.getLogger(__name__)                   # logging
if debug > 1:
  logging.basicConfig(level=logging.DEBUG)
elif debug > 0:
  logging.basicConfig(level=logging.INFO)


## checks if a value is no dict ##
def is_no_dict(values: Any) -> bool:
  return (
    values is None
    or (not isinstance(values, dict))
  )

## checks if a dict is empty ##
def is_empty_dict(values: Any) -> bool:
  return (
    values is None
    or (not isinstance(values, dict))
    or values == {}
  )

## checks if a value is no list ##
def is_no_list(values: Any) -> bool:
  return (
    values is None
    or (not isinstance(values, list))
  )

## checks if a list is empty ##
def is_empty_list(values: Any) -> bool:
  return (
    values is None
    or (not isinstance(values, list))
    or values == []
  )

## checks if a (str) value is empty ##
def is_empty(value: Any) -> bool:
  string = str(value)
  return (
    value is None
    or value            == []
    or value            == {}
    or string           == ""
    or string.lower()   == "none"
    or string.lower()   == "undefined"
    or string.lower()   == "nan"
    or string.lower()   == "no"
    or string.lower()   == "tbd"
    or string.lower()   == "n/a"
  )


## generates a list with unique elements ##
def unique(values: list) -> list:
  return(list(set(values)))

# read osib-YAML file
def read_osib_yaml(yaml_file: str):
  logger.info(f"read_osib_yaml({yaml_file}).")
  with open(yaml_file, 'r') as fin:
    _osib_yaml = yaml.safe_load(fin)
  logger.debug(f" -> OSIB YAML:\n{yaml.dump(_osib_yaml, sort_keys=False, indent=2, default_flow_style=False)}\n")
  return (_osib_yaml)


#################################################################################################################################################
# define_env(env):                                                                                                                              #
#   Read YAML file at the mkdocs signal define_env                                                                                              #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
def define_env(env):
  "Hook function"

  logger.info (f"MACRO (define_env): Call define_env(env)")
  logger.debug(f"MACRO (define_env): Environment-Config: {env.conf}")
  global osib_yaml                                                  # use global osib_yaml
  global debug
  global defaut_lang
  global categories_default
  global export_dir
  global latest_default
  global yaml_file
  global successors_default
  global successor_texts
  global osib_warnings

  logger.debug(f"MACRO (define_env): Environment-Config: get global default values from env.conf['extra']['osib']: {env.conf['extra']['osib']}")
  if (not is_empty(env.conf)) and ('extra' in env.conf) and ('osib' in env.conf['extra']):      # get global default values
    if 'debug' in env.conf['extra']['osib']:
      debug             = env.conf['extra']['osib']['debug']
      if debug > 1:
        logging.basicConfig(level=logging.DEBUG)
      elif debug > 0:
        logging.basicConfig(level=logging.INFO)
    if 'default_lang'     in env.conf['extra']['osib']:
      default_lang      = env.conf['extra']['osib']['default_lang']
    if 'categories'       in env.conf['extra']['osib']:
      categories_default= env.conf['extra']['osib']['categories']
    if 'export_dir'       in env.conf['extra']['osib']:
      export_dir        = env.conf['extra']['osib']['export_dir']
    if 'latest'           in env.conf['extra']['osib']:
      latest_default    = env.conf['extra']['osib']['latest']
    if 'yaml_file'        in env.conf['extra']['osib']:
      yaml_file         = env.conf['extra']['osib']['yaml_file']
    if 'successor_texts' in env.conf['extra']['osib']:
      for successors_lang, value in env.conf['extra']['osib']['successor_texts']:
        successor_texts[successors_lang] = value
    if 'split_to_texts'   in env.conf['extra']['osib']:
      for successors_lang, value in env.conf['extra']['osib']['split_to_texts']:
        successor_texts[successors_lang] = value
    logger.debug(f"MACRO (define_env): Environment-Config: set global default values:\n  - debug = {debug}\n  - default_lang = {default_lang}\n  - categories_default = {categories_default}\n  - export_dir = {export_dir}\n  - latest = {latest_default}\n  - yaml_file = {yaml_file}\n  - successor_texts = {successor_texts}\n  - split_to_texts = {split_to_texts}")

  if not osib_yaml:                                                 # global osib_yaml is not defined
    logger.debug(f"read OSIB YAML file '{yaml_file}'.")
    osib_yaml = read_osib_yaml(yaml_file)


#################################################################################################################################################
# _create_dict:                                                                                                                                 #
#   internal function that creates a dict leaf according to the path and adds optionally attributes                                             #
#   works with a copy of path to avoid to change the original path                                                                              #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _create_dict(yaml={}, path=[], **args):
    global osib_warnings
    attributes      = args.get('attributes',        {}          )   # default attribute is {}; if Attribute is a value, a dict or a list it will be added to the new object leaf
    get_attributes  = args.get('get_attributes',    False       )   # default is False; False: adds 'children' keys to the path for tree nodes, True: use original path
    caller_function = args.get('caller_function',   ""          )   # default caller_function is "", used for logging
    # Browses recursively through the yaml structure according to the path. Returns the value or the yaml branch found at the given path
    if debug > 1:
      logger.debug(f"{caller_function} _create_dict (path = '{path}', args = {args}')")

    if is_empty_list(path):
      if is_empty_dict(yaml):
        yaml = attributes
        if debug > 1:
            logger.debug(f"{caller_function} _create_dict(): return yaml={yaml}")
      else:
        logger.warning(f"{caller_function} _create_dict(): nothing to create return yaml={yaml}")
        osib_warnings += 1
      return(yaml)
    key = path[0]
    path.pop(0)
    if len(path) > 0:
      if not get_attributes:                                        # no attributes
        yaml[key] = {
                      'children': {}
                    }                                               # add dict as child of the higher level
        return(_create_dict(yaml[key]['children'], path, **args))
      else:
        yaml[key] = {}                                              # create next osib tree node
        if debug > 1:                                               # big debug
          logger.debug(f"{caller_function} _create_dict(): created yaml['{key}']={yaml[key]}")
        return(_create_dict(yaml[key], path, **args))
    else:
      yaml[key] = attributes
      if debug > 1:
        logger.debug(f"{caller_function} _create_dict(): return yaml['{key}']={yaml[key]}")
      return(yaml[key])
    # end if len(path)
  #end _create_dict


#################################################################################################################################################
# _lookup_yaml:                                                                                                                                  #
# Internal function to parse recursively through the yaml structure and lookup the requested elements.                                          #
# Adds missing path elements if arg 'create = True'                                                                                             #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _lookup_yaml(yaml={}, path=[], path_item=0, **args):
    global osib_warnings
    # Browses recursively through the yaml structure according to the path. Returns the value or the yaml branch found at the given path
    # changes the path list to aliases children if needed
    get_attributes  = args.get('get_attributes',    False       )   # default is False; False: adds 'children' keys to the path for tree nodes, True: use original path
    create          = args.get('create',            False       )   # default create is False; True: Creates missig elements of the path
# attributes does not seem useful as the calling function is not noticed if attributes has been added
    attributes      = args.get('attributes',        {}          )   # default attribute is None; if Attribute is a value, a dict or a list it will be added to the new object leaf if create = True
    caller_function = args.get('caller_function',   ""          )   # default caller_function is "", used for logging
    children        = 'children'                                    # used as key for lookups through the tree/nodes
    if debug > 1:                                                   # big_debug
      logger.debug (f"{caller_function} _lookup_yaml (yaml:<yaml>, path:'{path}', path_item:'{path_item}', get_attributes ='{get_attributes}', create ='{create}', attributes ='{attributes}')")
    if debug > 3:                                                   # huge_debug
      logger.debug(f"{caller_function} _lookup_yaml(): with yaml: '{yaml}'\n")
    if is_empty_list(path):                                         # path is empty => found
      return (yaml)
    if is_no_dict(yaml):                                            # yaml is no dict => not found
      logger.warning(f"{caller_function} _lookup_yaml(): yaml is no dict: path:'{path}' not generated'\n")
      osib_warnings += 1
      return ("")
    key=path[path_item]                                             # next key
    if not get_attributes:                                          # Osib_tree and Osib_nodes need an explicit attribute 'children' -> so we have to support this here
      if children in yaml:
        yaml = yaml[children]
      elif create:
        if debug >2:                                                # big debug
          logger.debug(f"   created element '{children}' for key '{key}'")
        yaml[children]  = {}                                        # add empty dict
        yaml            = yaml[children]
      else:                                                         # not found
        return ("")
    # classical yaml dict structure (no listed items)
    if isinstance(yaml, dict):
      if debug >2:                                                  # big debug
        logger.debug("   <yaml> is a dict")
      if (key not in yaml) and (not get_attributes):                # key is not in yaml and is no attribute -> check if key is an alias
        if debug >2:
          logger.debug(f" - {key}: search in 'aliases' lists of all yaml children")
        if debug >3:
          logger.debug(f"   -> yaml: '{yaml}'")
        for child in yaml:                                          # look for aliases in all peer children
          if debug >2:
            logger.debug(f"   ~ child '{child}'")
          if debug >3:
            logger.debug(f"     ~ yaml[{child}]: '{yaml[child]}'")
          if (isinstance(yaml[child], dict)) and ('aliases' in yaml[child]):
            if debug >3:
              logger.debug(f"     ~ yaml[{child}]['aliases']: '{yaml[child]['aliases']}'")
            if (key in yaml[child]['aliases']):                     # found key as alias of a child
              if debug >1:
                logger.info (f"   -> use (peer) alias for '{key}': '{child}'")
              key = child
              path[path_item] = child                               # Change actual path[path_item] to child (alias):
              if debug > 2:
                logger.debug (f"   -> path[{path_item}] = {path[path_item]}")
              break
            else:
              if debug >2:
                logger.debug(f"     ~ key '{key}' not found in aliases of 'yaml[{child}]': '{yaml[child]['aliases']}'")
          else:
            if debug >2:
              logger.debug(f"     ~ no aliases found for 'yaml[{child}]': '{yaml[child]}'")
        # end for child
      if key not in yaml:                                           # key stays not to be in yaml
        if create:                                                  # create missing path
          if debug >3:
            logger.debug(f'{caller_function} _lookup_yaml(): -> create osib-obj... \'{path}\' = {yaml}\n')
          elif debug >1:
            logger.debug(f'{caller_function} _lookup_yaml(): -> create osib-obj... \'{path}\'\n')
          return(_create_dict(yaml, path[path_item:], get_attributes = get_attributes, attributes = attributes, caller_function = caller_function))
        else:
          if debug >3:
            logger.debug(f"{caller_function} _lookup_yaml(): path '{path}' not found in '{yaml}'")
          elif debug >1:
            logger.debug(f"{caller_function} _lookup_yaml(): path '{path}' not found")
          return ("")                                               # nested key is not in yaml
      if debug >3:
        logger.debug(f" -> key '{key}': '{yaml[key]}'")
      elif debug >1:
        logger.debug(f" -> key '{key}': ")

      # get next path item and check if path is done
      path_item += 1;                                               # next path item
      if debug >2:
        logger.debug (f" ~ path[{path_item}:] = '{path}'")
      if not is_empty_list(path[path_item:]):                       # path is not empty => get next item
        return(_lookup_yaml (yaml[key], path, path_item, get_attributes = get_attributes, create = create, attributes = attributes, caller_function = caller_function))
      else:
        return (yaml[key])                                          # path is empty => found the key => Return the yaml value/remaining subtree
    # listed items within a yaml structure
    elif isinstance(yaml, list):
      if debug >2:                                                  # big debug
        logger.debug("<yaml> is a list")
      nr = 0
      for item in yaml:
        if debug >2:
          logger.debug (f"   path = '{path}'\n")
        nr += 1
        logger.debug(f" ~ {nr}. list item {item}\n")
        result = _lookup_yaml (item, path, path_item, get_attributes = get_attributes, create = create, attributes = attribute, caller_function = caller_function)
        if debug >2:                                                # big debug
          logger.debug (f"   path       = '{path[path_item:]}'\n")  # check if path is modifed
        if not is_empty_dict (result):                              # TBD: verify if more than the first found result is needed
          return(result)
      # empty list or not found
      if create:                                                    # create missing path
        if debug >2:                                                # big debug
          logger.debug(f'{caller_function} _lookup_yaml(): -> create osib-list-obj... \'{path}\' = {yaml}\n')
        new_item = {}
        yaml.append(new_item)
        return(_create_dict(new_item, path[path_item:], get_attributes = get_attributes, attributes = attributes, caller_function = caller_function))
      else:
        if debug >1:
          logger.debug(f"{caller_function} _lookup_yaml(): list item '{item}' not found in yaml[{item}]['aliases']: '{yaml[item]['aliases']}'")
        return ("")                                                 # nested key is not in yaml
  #end _lookup_yaml


#################################################################################################################################################
# _merge_links:                                                                                                                                 #
#     Internal function that merges link lists                                                                                                  #
#     Returns true if at least one Link has been added.                                                                                         #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _merge_links(links: list, new_links: list, **args) -> bool:
    change_update   = args.get('change_update',     "update"    )   # default change_update="update" => adds change="update"
    caller_function = args.get('caller_function',   ""          )   # default caller_function is "", used for logging
    global osib_warnings
    result          = False

    if debug >1:
      logger.debug(f"_merge_links: args       = {args}")
    for new_link_item in new_links:
      if ('type' not in new_link_item) or ('link' not in new_link_item):
        logger.warning(f">>> {caller_function} _merge_links(): 'type' or 'link' keys are missing in link '{new_link_item}'")
        osib_warnings += 1
        continue                                        # next new_link_item
      found_link = False
      for obj_link_item in links:
        if ('type' in obj_link_item) and ('link' in obj_link_item) and (obj_link_item['type'] == new_link_item['type']):
          if (obj_link_item['type'] == 'parent') and (obj_link_item['link'] != new_link_item['link']): # change parent
            new_link_item['change']    = change_update
            obj_link_item               = new_link_item
            result                      = True
            logger.info(f" {caller_function} _merge_links(): changed a parent link '{new_link_item}'")
            break                                       # exit for obj_link_item
          elif (obj_link_item['link'] == new_link_item['link']):                   # the link exists already
            found_link = True
            break                                       # exit for obj_link_item
      # end for obj_link_item
      if not found_link:
        links.append(new_link_item)
        result = True
        if debug >1:
          logger.info(f" {caller_function} _merge_links(): added link '{new_link_item}'")
    # end for new_link_item
    links.sort(key = lambda x: (types_list.index(x['type']), x['link']))                        # sort links (1) by order of types_list and (2) alphabetically by link
    if debug >2:
        logger.debug(f" {caller_function} _merge_links(): result = {result} => links '{links}'")
    return(result)
  # end _merge_links


#################################################################################################################################################
# _get_path_list:                                                                                                                               #
#     Internal function to get the path list from a '.' separated path string                                                                   #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _get_path_list(**args) -> list:
    path            = args.get('path',              ""          )   # default path is ""
    path_type       = args.get('path_type',         ""          )   # default path_type is ""
    caller_function = args.get('caller_function',   ""          )   # default caller_function is "", used for logging
    global osib_warnings
    path_list       = []

    if not is_empty(path):
      path_list = path.lower().split(".")                           # lower and split the path string
      length  = len(path_list)
      if debug >3:
        logger.debug(f" {caller_function} _get_path_list(): {path_type}: path.split() = {path_list}")
      i = 0
      while i < length:                                             # numbers are handeled as int values
        if ((path_list[i]).isnumeric()):
          path_list[i] = int(path_list[i])
        i += 1
      if debug >3:
        logger.debug(f"  path_list    = {path_list}")
      if path_list[0] != "osib":                                    # Path needs to start with 'osib'
        err_str = f">>> WARNING in {caller_function} _get_path_list(): {path_type} path is no osib-path: '{path_list}'."
        logger.error(err_str)
        return([])
    # end if is_empty(path)
    return(path_list)
  # end _get_path_list()

#################################################################################################################################################
# _add_reverse_links:                                                                                                                           #
#     Internal function that adds reverse links. Normalizes the links argument by replacing aliased path items.                                 #
#     Returns true if at least one Link has been added. The arg{'links'} might be mutated and normalized                                        #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _add_reverse_links(**args) -> bool:
    osib_id         = args.get('osib',              ""          )   # default osib is ""
    create_organization = args.get('create_organization', False )   # default is False
    links           = args.get('links',             []          )   # default osib is []
    change_new      = args.get('change_new',        "new"       )   # default change_new="new"       => adds change="new"
    change_update   = args.get('change_update',     "update"    )   # default change_update="update" => adds change="update"
    reviewed        = args.get('reviewed',          datestamp   )   # default reviewed=<datestamp>
    no_reverse      = args.get('no_reverse',        False       )   # default no_reverse = False; True: does not generate reverse links if any other value is set
    reverse_status  = args.get('reverse_status',    "automatically_generated")
    caller_function = args.get('caller_function',   ""          )   # default caller_function is "", used for logging
    result          = False
    global added_yaml_data                                          # use global counter for added_yaml_data
    global osib_warnings

    if debug >2:
      logger.debug (f"_add_reverse_links: args       = {args}")
    if osib_id and osib_id != "":
      for link_item in links:
        if (not is_empty(link_item['type'])):
          if debug >0:
            logger.debug(f"  {caller_function} _add_reverse_links: add reverse link from '{link_item['link']}' to '{reverse_types_dict[link_item['type']]}': '{osib_id}'")
          reverse_path = _get_path_list(path=link_item['link'], path_type="reverse link_item", caller_function=f"{caller_function} _add_reverse_links:")
          if not is_empty_list(reverse_path):
            # check if OSIB Object exists
            reverse_path_organization = reverse_path [1:2]          # [osib, organisation] is obligatory: check here for organization
            reverse_path_suffix       = reverse_path [2:]           # optional suffix, e.g. [<standard|project>, version, <local structure ...>]
            reverse_organization_obj  = _lookup_yaml (osib_yaml, reverse_path_organization, 0, create = create_organization, caller_function=f"{caller_function} _add_reverse_links:")
            if not is_no_dict(reverse_organization_obj):            # 'osib.organization' found
              if debug >2:
                logger.debug(f"  --> {caller_function} _add_reverse_links: found parent organization '{reverse_path[:2]}'")
              add_reverse_link_dict = {
                'link':        osib_id,                             # reverse link
                'type':        reverse_types_dict[link_item['type']],
                'status':      reverse_status,
                'reviewed':    reviewed,
                'change':      change_new
              }
              reverse_osib_obj = _lookup_yaml (reverse_organization_obj, reverse_path_suffix, 0, create = True, caller_function=f"{caller_function} _add_reverse_links:")
              if not is_no_dict (reverse_osib_obj):
                if debug >3:
                    logger.debug (f"  --> {caller_function} _add_reverse_links: found linked item {reverse_path}: reverse_osib_obj = {reverse_osib_obj}")
                elif debug >1:
                    logger.debug (f"  --> {caller_function} _add_reverse_links: found linked item {reverse_path}:")
                links_list = _lookup_yaml (reverse_osib_obj, ["attributes", "links"], 0, get_attributes = True, create = True, caller_function=f"{caller_function} _add_reverse_links:")  # get links list attribute from object
                ### Check if reverse link to anchor and type exists
                if not is_empty_list(links_list):
                  if _merge_links(links_list, [add_reverse_link_dict], caller_function=(f"{caller_function} -> _add_reverse_links: "), change_update=change_update): # add one list element
                    result = True
                    added_yaml_data += 1                            # count added data to yaml
                else:                                               # add new attribute 'links' list
                  reverse_osib_obj['attributes'] = {
                      'links': [ add_reverse_link_dict ]            # new list with a dict as 1st element
                  } # first list element
                  links_list = [ add_reverse_link_dict ]            # for logging
                  result = True
                  added_yaml_data += 1                              # count added data to yaml
                if debug >1:
                    logger.info(f"{caller_function} _add_reverse_links: -> reverse link to type '{link_item['type']}' at '{link_item['link']}':\n- {yaml.dump(add_reverse_link_dict, sort_keys=False, indent=2, default_flow_style=False)}")
                if debug >3:
                    logger.debug(f"{caller_function} _add_reverse_links:   => '{link_item['type']}'s links:\n{yaml.dump(links_list, sort_keys=False, indent=2, default_flow_style=False)}")
              else:                                                 # add new attribute with 'links' list
                reverse_osib_obj['attributes'] = {
                    'links': [ add_reverse_link_dict ]              # new list with a dict as 1st element
                } # first list element
                links_list = [ add_reverse_link_dict ]              # for logging
                result = True
                added_yaml_data += 1                                # count added data to yaml
                if debug >1:
                  logger.info(f"{caller_function} _add_reverse_links: -> reverse link to type '{link_item['type']}' at '{link_item['link']}':\n- {yaml.dump(add_reverse_link_dict, sort_keys=False, indent=2, default_flow_style=False)}")
                if debug >3:
                  logger.debug(f"{caller_function} _add_reverse_links:   => '{link_item['type']}'s links:\n{yaml.dump(links_list, sort_keys=False, indent=2, default_flow_style=False)}")
              # normalize link_item['link']
              if debug >2:                                          # big debug
                logger.debug(f"    link_item['link'](raw):        {link_item['link']}")
              normalized_path   = reverse_path[0:1] + reverse_path_organization + reverse_path_suffix
              link_item['link'] = '.'.join(map(str,normalized_path))# update the link item by the normalized path
              if debug >2:                                          # big debug
                logger.debug(f"    link_item['link'](normalized): {link_item['link']}")
              # end normalize
            else:
              logger.warning(f">>> {caller_function} _add_reverse_links: WARNING at osib '{reverse_path}': reverse_path_organization '{reverse_path_organization}' neither found nor created")
              osib_warnings += 1
          # end if not is_empty_list(reverse_path)
        # end if link_item['type']
      # end for link_item
    # end if osib_id
    return (result)


#################################################################################################################################################
# _normalize_osib:                                                                                                                              #
#     Internal function to normalize an osib path: To be used for the variables osib, link and alias-element                                    #
#     (lower a string, replace one or more whitespaces by space, remove leading and trailing whitespaces)                                       #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _normalize_osib(osib, **args) -> str:
    caller_function     = args.get('caller_function',       ""          )   # default caller_function is "", used for logging
    global osib_warnings

    if debug >3:                                                    # debug
      logger.debug(f"    {caller_function} _normalize_osib: osib '{osib}'")
    if isinstance(osib, str):
      osib_new = re.sub (r"_", " ", osib)                             # replace underline by space
      osib_new = re.sub (r"\s+", " ", osib_new)                       # replace one or more whitespaces by space
      osib_new = osib_new.lower().strip()                             # lower all characters, remove all leading anid trailing spaces
      if debug >1:                                                    # debug
        logger.debug(f"    {caller_function} _normalize_osib: osib '{osib}' -> '{osib_new}'")
      return(osib_new)
    else:
      if debug >1:                                                    # debug
        logger.debug(f"    {caller_function} _normalize_osib: osib '{osib}' -> is no string: nothing to do")
      return(osib)
  # end _normalize_osib_


#################################################################################################################################################
# _get_named_source:                                                                                                                            #
#     Internal function to get the source URL and source name for lang or default_lang                                                          #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _get_named_source(osib_obj, **args) -> dict:
    lang                = args.get('lang',                  default_lang)   # default language is <default_language>
    caller_function     = args.get('caller_function',       ""          )   # default caller_function is "", used for logging
    source              = ""
    source_name         = ""
    default_source_dict = None
    global osib_warnings

    if debug >1:                                                    # debug
      logger.debug(f"{caller_function} _get_named_source: osib_obj '{osib_obj}', args = {args}")
    source_dict           = _lookup_yaml (osib_obj, ["attributes", "sources_i18n", lang], 0, get_attributes = True)  # get lang's source from object
    if (not is_empty_dict(source_dict)) and ('source' in source_dict):
      source = source_dict['source']
    else:
      if debug >1:                                                  # big debug
        logger.debug(f"{caller_function} _get_named_source(): no source url for lang '{lang}', try default lang '{default_lang}'; osib_obj: '{osib_obj}'")
      default_source_dict   = _lookup_yaml (osib_obj, ["attributes", "sources_i18n", default_lang], 0, get_attributes = True)  # get default_lang's source from object
      if (not is_empty_dict(default_source_dict)) and ('source' in default_source_dict):
        source = default_source_dict['source']
      else:
        logger.warning(f">>> {caller_function} _get_named_source(): Warning any source url found neither for lang '{lang}' nor for default_lang '{default_lang}'; osib_obj: '{osib_obj}'")
        osib_warnings += 1
    if (not is_empty_dict(source_dict)) and ('name' in source_dict):
      source_name = source_dict['name']
    else:
      if debug >1:                                                  # big debug
        logger.debug(f"{caller_function} _get_named_source(): no source name for lang '{lang}', try default lang '{default_lang}'; osib_obj: '{osib_obj}'")
      if (is_empty_dict(default_source_dict)):
        default_source_dict   = _lookup_yaml (osib_obj, ["attributes", "sources_i18n", default_lang], 0, get_attributes = True)  # get default_lang's source from object
      if (not is_empty_dict(default_source_dict)) and ('name' in default_source_dict):
        source_name = default_source_dict['name']
      else:
        logger.debug(f"{caller_function} _get_named_source(): any source name found neither for lang '{lang}' nor for default_lang '{default_lang}'; osib_obj: '{osib_obj}'")
    return({
            'source':       source,
            'source_name':  source_name
          })
  # end _get_named_source



#################################################################################################################################################
# _get_latest_links:                                                                                                                            #
#     Internal function to get the susseccor(s) of an osib node object                                                                          #
# (C) OWASP/The Top10-Team                                                                                                                      #
#################################################################################################################################################
  def _get_latest_links(**args) -> bool:
    osib_obj:dict       = args.get('osib_obj',              {}          )  # default node is {}
    latest_links:links  = args.get('latest_links',          []          )  # default latest_link is []
    lang:str            = args.get('lang',                  default_lang)  # default lang is <default_lang>
    caller_function:str = args.get('caller_function',       ""          )  # default caller_function is "", used for logging
    found               = False
    found_links         = []
    global osib_warnings

    if debug >2:                                                    # big debug
      logger.debug(f"{caller_function} _get_latest_links(): args: '{args}'")
    if is_empty_dict(osib_obj):
      logger.debug(f"{caller_function} _get_latest_links(): next osib_id is empty --> return found='False'")
      return(False)                                                 # is empty
    links = _lookup_yaml (osib_obj, ["attributes", "links"], 0, get_attributes = True)  # get links from object
    if is_empty_list(links):
      if debug >2:                                                  # big debug
        logger.debug(f"{caller_function} _get_latest_links(): no next links --> return found='False'")
      return(False)                                                 # is empty or not found
    for i in range(len(links)-1, -1, -1):                           # backward iteration to 0 (if len > 1)
      link_item = links[i]
      if ('link' in link_item) and ('type' in link_item) and (link_item['type'] in ['successor', "merged_to", "split_to" ]):
        link_id      = _normalize_osib(link_item['link'], caller_function="_get_latest_links")
        link_id_path = _get_path_list(path=link_id, path_type="link_id", caller_function=f"{caller_function} _get_latest_links:")
        if is_empty_list(link_id_path):
          err_str = f">>> WARNING in {caller_function} _get_latest_links(): successor link type '{link_item['type']}': path is no osib-path: '{link_id}'. Fall back to previous successor."
          logger.warning(err_str)
          osib_warnings += 1
          if debug >0:                                              # debug
            logger.debug(f"{caller_function} _get_latest_links():  --> return found='False'")
          return(False)                                             # The previous link is the latest valid successor
        osib_link_obj = _lookup_yaml (osib_yaml, link_id_path, 1)
        ### Mutate link_item
        if debug >2:                                                # big debug=
          logger.debug(f"  {caller_function} _get_latest_links(): link_item['link'](original):   {link_item['link']}")
        link_item['link'] = '.'.join(map(str,link_id_path))         # update the link item by the normalized path ### TBD: check if this is too much
        if debug >2:                                                # big debug
          logger.debug(f"  {caller_function} _get_latest_links(): link_item['link'](normalized): {link_item['link']}")
        ### End Mutate
        if is_empty_dict(osib_link_obj):                            # did not find the successor's tree node
          err_str = f">>> WARNING in {caller_function} _get_latest_links(): successor link type '{link_item['type']}': is no valid osib tree node: '{link_id}'. Fall back to previous successor."
          logger.warning(err_str)
          osib_warnings += 1
          if debug >1:                                              # debug
            logger.debug(f"{caller_function} _get_latest_links():  --> return found='False'")
          return(False)                                             # The previous link is the latest valid successor
        if debug >2:                                                # debug
          logger.debug(f"{caller_function} _get_latest_links():  --> found: '{osib_link_obj}' --> try to get next successor")
        result          = _get_latest_links(osib_obj=osib_link_obj, latest_links=latest_links, caller_function=caller_function)
        if not result:                                              # the susseccor link is not valid
          named_source_dict = _get_named_source(osib_link_obj, lang=lang, caller_function=f"{caller_function} _get_latest_links:")
          if (not is_empty_dict (named_source_dict)) and ('source' in named_source_dict) and (not is_empty(named_source_dict['source'])):   # link has a source
            found_links.append(link_item)                           # collect all found links to a temporary list
            if debug >3:                                            # big debug
              logger.debug(f"{caller_function} _get_latest_links():  --> found_link -> add '{link_item}' to temp list.")
        else:
          found = True                                              # found links of sussessors already
        if link_item['type'] != 'split_to':                         # no more successors expected
          break                                                     # exit for i
      # end if ('link' in link_item) and ...
    # end for i
    # no errors occured at any link_item
    if not is_empty_list(found_links):
      if debug >1:                                                  # debug
        logger.debug(f"{caller_function} _get_latest_links():  --> valid successors --> merge temp link list '{found_links}' with found_links '{latest_links}'.")
      _merge_links(latest_links, found_links)
      return(True)
    else:                                                           # did not find any successors
      if debug >1:                                                  # debug
        logger.debug(f"{caller_function} _get_latest_links():  --> return found='{found}'")
      return(found)
  # end:_get_latest_links


  @env.macro
  ###############################################################################################################################################
  # macro osib_anchor:        Adds an OSIB anchor and an object to an osib YAML structure                                                       #
  #                           Input:  osib_anchor(osib=osib.<organization>.<project|standard>.version(without dots '.')>.<internal structure>,  #
  #                                               create_organization=False, source=https://owasp.org/Top10/..., name='OWASP Top10',            #
  #                                               lang=<lang>, source_id=<source id>, parent=<osib-id>, ...)                                    #
  #                           Output: '<a id="<osib>"></a>'                                                                                     #
  # (C) OWASP/The Top10-Team, 2021                                                                                                              #
  ###############################################################################################################################################
  def osib_anchor(**args):
    global added_yaml_data                                              # use global counter for added_yaml_data
    global osib_yaml                                                    # use global osib_yaml
    global osib_warnings

    logger.info (f"Call MACRO osib_anchor():")
    if debug > 2:                                                       # big_debug
      logger.info (f"  args(raw)  = {args}")
    args = {
      k.lower(): v    for k, v in args.items()                          # normalize keys to small letters
    }
    osib_id         = args.get('osib',              "osib"      )       # default osib is "osib"
    create_organization = args.get('create_organization', False )       # default is False
    source_id       = args.get('id',                ""          )       # default source_id is ""
    source          = args.get('source',            ""          )       # default source is ""; http-link to source
    parent          = args.get('parent',            ""          )       # default parent is ""; osib-id of parent object
    lang            = args.get('lang',              default_lang)       # default lang is <default_lang>
    name            = args.get('name',              ""          )       # default names string is ""
    description     = args.get('description',       ""          )       # default description string is ""
    aliases         = args.get('aliases',           []          )       # default aliases list is []
    categories      = args.get('categories',        categories_default) # default categories list is []
    maturity        = args.get('maturity',          ""          )       # default maturity string is ""
    protection_need = args.get('protrection need',  ""          )       # default protection_need string is ""
    cre             = args.get('cre',               ""          )       # default cre string is ""
    status          = args.get('status',            "active"    )       # default status="active"
    change_new      = args.get('change_new',        "new"       )       # default change_new="new"       => adds change="new"
    change_update   = args.get('change_update',     "update"    )       # default change_update="update" => adds change="update"
    reviewed        = args.get('reviewed',          datestamp   )       # default reviewed=<datestamp>
    previous        = args.get('previous',          ""          )       # alias for predecessor, default previous is ""
    predecessor     = args.get('predecessor',       previous    )       # default predecessor is ""
    merged_from     = args.get('merged_from',       []          )       # default merged_from is []
    split_from      = args.get('split_from',        ""          )       # default split_from is ""
    no_reverse      = args.get('no_reverse',        False       )       # default no_reverse = False; True: does not generate reverse links if any other value is set
    reverse_status  = args.get('reverse_status',    "automatically_generated")
    silent          = args.get('silent',            False       )       # default is "" -> no output if any other value is set
    result_str      = ""
    help_str        = f'use osib_anchor(osib="osib.<organization>.<project|standard>.version(without dots \'.\')>.<internal structure>", create_organization=False, source="https://owasp.org/Top10/...", aliases=\["<osib-list>", ...\], name="<page/requirement/article name>", description="<description>", categories=[<category, ...], matutity="<maturity>", protection_need="<protection_need>", cre="<osib-id>" status="<status>", lang="<lang>", source="<source>", parent="<osib-id>", predecessor="<osib-id>", merged_from=\["<osib-list>", ...\], split_from="<split_from>", no_reverse=False, reverse_status="<reverse_status>", silent=False...'
    # end parameters
    osib_id         = _normalize_osib(osib_id, caller_function="osib_anchor")

    logger.info (f"  args       = {args}")
    if debug > 2:                                                   # big_debug
      logger.info (f"  lang       = {lang}\n  categories = {categories}\n  datestamp  = {datestamp}")
    invalid_keys = [k for k in args if k not in ['osib', 'create_organization', 'id', 'source', 'parent', 'lang', 'name', 'description', 'aliases', 
                                                 'categories', 'maturity', 'protection_need', 'cre', 'status', 'change_new', 'change_update', 'reviewed',
                                                 'previous', 'predecessor', 'merged_from', 'split_from', 'no_reverse', 'reverse_status', 'silent']]
    if not is_empty_list(invalid_keys):
      err_str=f">>> MACRO osib_anchor(): invalid key(s) '{invalid_keys}' in args '{args}' ignored;\n{help_str}"
      logger.warning(err_str)
      osib_warnings += 1

    invalid_values = [k for k in args if (not args[k]) or (args[k] is None)]
    if not is_empty_list(invalid_values):
      err_str=f">>> MACRO osib_anchor(): undefined values(s) in keys '{invalid_values}' of args '{args}';\n{help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return (f"<!--- {err_str} --->")
    if is_no_list(merged_from):
      err_str=f">>> MACRO osib_anchor(): 'merged_from' needs to be a list [<osib-list>, ...];\n{help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return (f"<!--- {err_str} --->")
    if is_no_list(aliases):
      err_str=f">>> MACRO osib_anchor(): 'aliases' needs to be a list [<osib-list>, ...];\n{help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return (f"<!--- {err_str} --->")
    if not is_empty_dict(env.page):                                 # get page information from macro plugin
      page = env.page
    else:
      page = "--unknown--"
    logger.debug(f"Page: '{env.page}'")

    if is_empty(osib_id):                                           # is an empty string
      err_str = f"MACRO osib_anchor(): 'osib' id is missing or empty: name='{name}', source='{source}'.\n{help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return(f'<!--- {err_str} --->')
    if is_empty(source):                                            # is an empty string
      err_str = f"MACRO osib_anchor(): 'source' is missing or empty: osib='{osib_id}', name='{name}'.\n{help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return(f'<!--- {err_str} --->')
    if not osib_yaml:                                               # global osib_yaml is not defined
      osib_yaml = read_osib_yaml(yaml_file)
    id_path = _get_path_list(path=osib_id, path_type="osib_id", caller_function=f"MACRO osib_anchor():")
    if is_empty_list(id_path):
      err_str = f"MACRO osib_anchor(): no osib path '{osib_id}' in OSIB YAML file.\n{help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return(f'<!--- {err_str} --->')
    # check if OSIB Object exists
    id_path_organization = id_path [1:2]                            # [osib, organisation] is obligatory: check here for organization
    id_path_suffix       = id_path [2:]                             # optional suffix, e.g. [<standard|project>, version, <local structure ...>]
    organization_obj     = _lookup_yaml (osib_yaml, id_path_organization, 0, create = create_organization, caller_function=f"MACRO osib_anchor():")
    if is_no_dict(organization_obj):                                # no 'osib.organization' found nor created
      err_str = f"MACRO osib_anchor(): Organization '{id_path[:2]}' not found in OSIB YAML file. {help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return(f'<!--- {err_str} --->')
    if debug >2:                                                    # big_debug
      logger.debug(f"MACRO osib_anchor():   --> found orgaization '{id_path[:2]}'")
    osib_obj = _lookup_yaml (organization_obj, id_path_suffix, 0, create = True, caller_function=f"MACRO osib_anchor():")
    if debug >3:                                                    # huge_debug
      logger.debug (f"MACRO osib_anchor():   --> found osib-item {id_path}: osib_obj = {osib_obj}")
    attributes_dict                                           = {}                              # prepare attributes dict
    if not is_empty(source_id):
      attributes_dict['source_id']                            = source_id
      if debug >2:                                                  # big_debug
        logger.debug(f"MACRO osib_anchor(): source_id = {source_id}")
    if not is_empty_list(categories):
      attributes_dict['categories']                           = categories
      if debug >2:                                                  # big_debug
        logger.debug(f"MACRO osib_anchor(): categories = {categories}")
    if not is_empty(maturity):
      attributes_dict['maturity']                             = maturity
      if debug >2:                                                  # big_debug
        logger.debug(f"MACRO osib_anchor(): maturity = {maturity}")
    if not is_empty(protection_need):
      attributes_dict['protection_need']                      = protection_need
      if debug >2:                                                  # big_debug
        logger.debug(f"MACRO osib_anchor(): protection_need = {protection_need}")
    if (not is_empty(lang)):
      attributes_dict['sources_i18n']                         = { lang: {} }
      if not is_empty(name):
        attributes_dict['sources_i18n'][lang]['name']         = name
      else:
        logger.warning(f"MACRO osib_anchor(): osib-item '{id_path}': lang '{lang}': name is missing; {help_str}")
        osib_warnings += 1
      if not is_empty(source):
        attributes_dict['sources_i18n'][lang]['source']       = source                          # url
      else:
        logger.warning(f"MACRO osib_anchor(): osib-item '{id_path}': lang '{lang}': source url is missing; {help_str}")
        osib_warnings += 1
      if not is_empty(description):
        attributes_dict['sources_i18n'][lang]['description']  = description
      if not is_empty(status):
        attributes_dict['sources_i18n'][lang]['status']       = status
      if not is_empty(reviewed):
        attributes_dict['sources_i18n'][lang]['reviewed']     = reviewed
      if debug >2:
        logger.debug(f"  attributes_dict['sources_i18n'] = {attributes_dict['sources_i18n']}")
    attributes_dict['links']                                  = []                              # define an empty list for links as placeholder to hold this position
    if not is_empty(parent):
      attributes_dict['links'].append(                          {                               # add parent
                                                                    'link':      parent,
                                                                    'type':      "parent",
                                                                    'status':    status,
                                                                    'reviewed':  reviewed,
                                                                    'change':    change_new
                                                                }
                                     )
    if not is_empty(predecessor):                                                               # add predecesor
      attributes_dict['links'].append(                         {
                                                                   'link':      predecessor,
                                                                   'type':      "predecessor",
                                                                   'status':    status,
                                                                   'reviewed':  reviewed,
                                                                   'change':    change_new
                                                               }
                                     )
    elif not is_empty_list(merged_from):                                                        # merged_from (list)
      for merged_item in merged_from:
        attributes_dict['links'].append(                       {
                                                                   'link':      merged_item,
                                                                   'type':      "merged_from",
                                                                   'status':    status,
                                                                   'reviewed':  reviewed,
                                                                   'change':    change_new
                                                               }
                                       )
      # End for merged_item
    elif not is_empty(split_from):                                                              # add split_from
      attributes_dict['links'].append(                         {
                                                                   'link':      split_from,
                                                                   'type':      "split_from",
                                                                   'status':    status,
                                                                   'reviewed':  reviewed,
                                                                   'change':    change_new
                                                               }
                                     )
    if not is_empty(cre):
      attributes_dict['links'].append(                          {                               # add cre
                                                                    'link':      cre,
                                                                    'type':      "reference",
                                                                    'status':    status,
                                                                    'reviewed':  reviewed,
                                                                    'change':    change_new
                                                                }
                                     )
    if debug >2:
        logger.debug(f"  attributes_dict['links'] = {attributes_dict['links']}")
    # end add links
    if not is_empty(status):
      attributes_dict['status']                               = status
      if debug >2:                                                  # big_debug
        logger.debug(f"MACRO osib_anchor(): status = {status}")
    if not is_empty(reviewed):
      attributes_dict['reviewed']                             = reviewed
      if debug >2:                                                  # big_debug
        logger.debug(f"MACRO osib_anchor(): reviewed = {reviewed}")
    if not is_empty(change_new):
      attributes_dict['change']                               = change_new
      if debug >2:                                                  # big_debug
        logger.debug(f"MACRO osib_anchor(): change = {change_new}")
    # 'children' will get the last position, if they will be created later
    if osib_obj == {} or isinstance(osib_obj, dict):                # found an dict object
      if debug >2:                                                  # big_debug
        logger.debug(f'  --> found osib_obj \'{id_path}\': {osib_obj}')
#     Add reverse links: at least at this position to get the links normalized before they are copied (they get mutated)
      if (not no_reverse) and (not is_empty(parent)):
        # normalize args['osib']
        if debug >2:                                                # big debug
          logger.debug(f"    args['osib'](raw)    =    {args['osib']}")
          logger.debug(f"    id_path_organization =    {id_path_organization}")
          logger.debug(f"    id_path_suffix       =    {id_path_suffix}")
        reverse_path    = id_path[0:1] + id_path_organization + id_path_suffix
        new_osib        = '.'.join(map(str,reverse_path))           # update the osib argument by the normalized path
        if debug >3:                                                # big debug!
          logger.debug(f"    args                 =    {args}")
          logger.debug(f"    osib                 =    {new_osib}")
        args['osib'] = new_osib
        if debug >2:                                                # big debug!
          logger.debug(f"    args['osib'](normalized)= {args['osib']}")
        if debug >3:                                                # huge debug!
          logger.debug(f"    args                 =    {args}")

        if _add_reverse_links(**args, links=attributes_dict['links'], caller_function="osib_anchor(): "): # add one list element
          if debug >2:                                              # big_debug
            logger.info(f"osib_anchor(): -> added reverse links of {osib_id}")
      # end if no_reverse
      # copy or update aliases
      if not is_empty_list(aliases):
        aliases                                   = [_normalize_osib(a, caller_function="osib_anchor(aliases)") for a in aliases]    # normalize all aliases
        if debug >3:                                                # big_debug
          logger.debug(f"MACRO osib_anchor(): add aliases = {aliases}")
        if 'aliases' not in osib_obj:
          osib_obj['aliases']                     = aliases         # copy attributes to dict
          if debug >2:                                              # big_debug
            logger.debug(f"MACRO osib_anchor(): created aliases = {aliases}")
        else:
          for alias in aliases:
            if (alias not in osib_obj['aliases']) and (alias != reverse_path[-1]):                      # alias is not in the alias list and not the actual (normalized) OSIB element
              osib_obj['aliases'].append(alias)
              if debug >3:                                          # huge_debug
                logger.debug(f"MACRO osib_anchor(): add alias = {alias}")
          if debug >2:                                                # big_debug
            logger.debug(f"MACRO osib_anchor(): updated aliases list osib_obj['aliases']: '{osib_obj['aliases']}'")
      # end copy or update aliases
      # update or copy attributes
      if 'attributes' not in osib_obj:
        osib_obj['attributes'] = attributes_dict                    # copy attributes to dict
      else:
        change = change_new
        for key in attributes_dict:                                 # check for new keys or values
          if key in ['change','reviewed']:
            continue                                                # do update status values on base of a different change variabels or review
          elif key in ['sources_i18n']:                             # i18n string keys
            if (key not in osib_obj['attributes']):
              osib_obj['attributes'][key] = attributes_dict[key]    # initialize key directory with new values
            elif (lang not in osib_obj['attributes'][key]):
              osib_obj['attributes'][key][lang] = attributes_dict[key][lang]                    # initialize key's lang directorya with new values
              if debug >2:
                logger.debug(f"  added language '{lang}': {osib_obj['attributes'][key][lang]}")
            else:
              for sub_key in ['name', 'source', 'description']:
                sub_change = change_new
                if (sub_key in attributes_dict[key][lang]) \
                and ( (sub_key not in osib_obj['attributes'][key][lang]) \
                      or (osib_obj['attributes'][key][lang][sub_key] != attributes_dict[key][lang][sub_key]) \
                    ): # new data and/or changed
                   osib_obj['attributes'][key][lang][sub_key] = attributes_dict[key][lang][sub_key]
                   sub_change = change_update
              if sub_change == change_update:
                osib_obj['attributes'][key][lang]['status']   = status
                osib_obj['attributes'][key][lang]['reviewed'] = reviewed
                osib_obj['attributes'][key][lang]['change']   = sub_change
          elif key in ['links']:
            if ('links' not in osib_obj['attributes']):
              osib_obj['attributes']['links']                 = attributes_dict['links']
            else:
              _merge_links(osib_obj['attributes']['links'], attributes_dict['links'])
          elif (key not in osib_obj['attributes']) or (osib_obj['attributes'][key] != attributes_dict[key]):  # check key, value pairs
            if debug >2:
              if key not in osib_obj['attributes']:
                logger.debug(f"  add attribute '{key}' = '{attributes_dict[key]}'")
              else:
                logger.debug(f"  change attribute for key '{key}' from '{osib_obj['attributes'][key]}' to '{attributes_dict[key]}'")
            osib_obj['attributes'][key]                       = attributes_dict[key]
            change = change_update
          # end if key...
          if key in osib_obj["attributes"]:
            if debug >2:                                            # big_debug
              logger.debug(f"MACRO osib_anchor():  --> osib_obj['attributes']['{key}'] = {osib_obj['attributes'][key]}")
          else:
            logger.debug(f"MACRO osib_anchor():  --> osib_obj['attributes']['{key}']: key '{key}' does not exist")
        # end for key
        if change == change_update:
          osib_obj['attributes']['status']                    = status
          osib_obj['attributes']['reviewed']                  = reviewed
          osib_obj['attributes']['change']                    = change
        if debug >2:                                                # big_debug
          logger.debug(f"  --> osib_obj['attributes']['change'] = {osib_obj['attributes']['change']}")
      # end if 'attributes' ... else:
      # end update or copy attributes
    else:
      logger.warning(f'>>> WARNING at osib \'{id_path}\': {osib_obj} neither found nor created')
      osib_warnings += 1
    result_str = "<a id=\"" + osib_id + "\"></a>"                   # html anchor
    added_yaml_data += 1                                            # count added data to yaml (potentially)
    logger.info (f"==> osib_anchor(): {result_str},\n                    osib_obj '{osib_id}' = {osib_obj}\n")
    if debug >3:                                                    # huge debug
      logger.debug(f"==> osib_anchor(): osib_yaml: '{osib_yaml}\n====================================================\n")
    if not silent:
      return(result_str)
    else:
      return("")
  # end osib_anchor()


  @env.macro
  ###############################################################################################################################################
  # macro osib_link:          Get links from osib YAML structure and add it optionally to an exported YAML file                                 #
  #                           Input:  osib_link(link=osib.<organization>.<project|standard>.version(without dots '.')>.<internal structure>,    #
  #                                             doc=<osib>, osib=<osib>, create_organizatio>=True, ...                                          #
  #                           Output: markdown link format '["<text>|<prefix><doc_osib><doc_suffix><osib_names>"](<html_link>)<speparator> ..'  #
  # (C) OWASP/The Top10-Team, 2021                                                                                                              #
  ###############################################################################################################################################
  def osib_link(**args):
    logger.info (f"Call MACRO osib_link():")
    if debug > 2:                                                   # big_debug
      logger.info (f"  args(raw)  = {args}")
    args = {
      k.lower(): v    for k, v in args.items()                      # normalize keys to small letters
    }
    link_id         = args.get('link',          ""          )       # osib link, default link is ""
    link_id         = _normalize_osib(link_id, caller_function="osib_link(link_id)")
    create_organzation = args.get('create_organization',  False )   # default is False
    lang            = args.get('lang',          default_lang)       # default language is <default_language>
    latest          = int(args.get('latest',    latest_default))    # latest_default is a global variable
                                                                    #         0: Get link_id, do not follow links to latest versions
                                                                    #         1: Log a warning, if successor(s) of link_id exist
                                                                    #         2: Add the latest version(s), if successor(s) exist, log an info
                                                                    #         3: show only the latest version, if *one* successor exist.
                                                                    #            Add latest versions if more split versions exist (see 2), log an info
    text            = args.get('text',          ""          )       # default text is "" -> use prefix, doc, doc_suffix, link_names
    prefix          = args.get('prefix',        ""          )       # default prefix = ""
    separator       = args.get('separator',     ", "        )       # default separator = ""
    doc_default     ='.'.join(map(str,link_id.split(".")[0:3]))
                                                                    # default doc is the links 3rd level path element, e.g. osib.owasp.top10
    doc             = args.get('doc',           doc_default )       # doc osib link, default doc = ""
    doc             = _normalize_osib(doc, caller_function="osib_link(doc)")
    doc_suffix      = args.get('doc_suffix',    ": "        )       # default doc_suffix = ": "
    osib            = args.get('osib',          ""          )       # default osib = ""; If osib=<osib> is an existing osib it adds the requested link bidirectionally
                                                                    #                    to the source and destination subtrees to a copy the yaml structure if it has not been added before.
    osib            = _normalize_osib(osib, caller_function="osib_link(osib)")
    type            = args.get('type',          "reference" )       # default type = "reference"; Adds the link to 'osib' as an reference; adds an reverce link according the reverse_types_dict)
    status          = args.get('status',        "active"    )       # default status="active" => adds link status="active"
    change_new      = args.get('change_new',    "new"       )       # default change_new="new"       => adds change="new"
#   change_update  = args.get('change_update', "update" )           # default change_update="update" => adds change="update"
    reverse_status  = args.get('reverse_status', "automatically_generated")
                                                                    # default reverse_status="automatically_generated" => adds reverse link status="automatically_generated"
    reviewed        = args.get('reviewed',      datestamp   )       # default reviewed=<datestamp>
    no_reverse      = args.get('no_reverse',    False       )       # default no_reverse = False; True: does not generate reverse links if any other value is set
    silent          = args.get('silent',        False       )       # default is False -> output; True: no output
    global osib_warnings

    result_str      = ""
    doc_str         = ""
    help_str        = f'use osib_link(link="osib.<organization>.<project|standard>.version(without dots \'.\')>.<internal structure>", doc="<osib>", text="<text>", osib="<osib>", type="<type>", status="<status>", lang="<lang>", no_reverse=False, reverse_status="<reverse_status>", silent=False...'
    global added_yaml_data                                          # use global counter for added_yaml_data
    global osib_yaml                                                # use global osib_yaml
    # end parameters
    caller_function = "MACRO osib_link(): "                         # for debugging

    logger.info (f"  args       = {args}")
    invalid_keys = [k for k in args if k not in ['link', 'lang', 'latest', 'text', 'prefix', 'separator', 'doc', 'doc_suffix', 'osib', 'create_organization',
                                                 'type', 'status', 'change_new', 'reverse_status', 'reviewed', 'no_reverse', 'silent']]
    if not is_empty_list(invalid_keys):
      err_str=f">>> MACRO osib_link(): invalid key(s) '{invalid_keys}' in args '{args}' ignored; {help_str}"
      logger.warning(err_str)
      osib_warnings += 1

    invalid_values = [k for k in args if (args[k] is None)]
    if not is_empty_list(invalid_values):
      err_str=f">>> MACRO osib_link(): undefined values(s) in keys '{invalid_values}' of args '{args}'; {help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return (f"<!--- {err_str} --->")

    if not is_empty_dict(env.page):                                 # get page information from macro plugin
      page = env.page
    else:
      page = "--unknown--"
    logger.debug(f"Page: '{env.page}'")

    if not osib_yaml:                                               # global osib_yaml is not defined
      osib_yaml = read_osib_yaml(yaml_file)
    if is_empty (link_id):
      err_str = f">>> Error in MACRO osib_link(): osib ID is missing or empty: {help_str}"
      logger.warning (err_str)
      osib_warnings += 1
      return(f'<!--- {err_str} --->')
    link_id_path = _get_path_list(path=link_id, path_type="link_id", caller_function=caller_function)
    if is_empty_list(link_id_path):
      err_str = f">>> Error in MACRO osib_link(): path is no osib path '{link_id}': {help_str}"
      logger.warning(err_str)
      osib_warnings += 1
      return(f'<!--- {err_str} --->')
#   get doc
    if doc and (doc != "") and (len(link_id_path) >3):              # doc needs to be defined, not empty, and the link ID needs to be at least a path with depth 4
      doc_path   = _get_path_list(path=doc, path_type="doc", caller_function=caller_function)
      if is_empty_list(doc_path):
        err_str = f">>> Warning in MACRO osib_link(): doc path is no osib-path: '{doc}': '{help_str}'."
        logger.warning(err_str)
        osib_warnings += 1
      else:
        osib_doc_obj  = _lookup_yaml (osib_yaml, doc_path, 1)
        doc_str       = _lookup_yaml (osib_doc_obj, ['attributes', 'sources_i18n', lang, 'name'], 0, get_attributes = True)
        if (doc_str is None or doc_str == "") and lang != default_lang:
          doc_str     = _lookup_yaml (osib_doc_obj, ['attributes', 'sources_i18n', default_lang, 'name'], 0, get_attributes = True)
        if doc_str and doc_str != "":
          doc_str += doc_suffix                                     # add doc_suffix, e.g. ': '

#   get osib_link_obj (main object)
    successor_str         = ""
    latest_links          = []
    link                  = ""
    link_name             = ""
    osib_link_obj = _lookup_yaml (osib_yaml, link_id_path, 1)
    if not (is_empty_dict(osib_link_obj)):                          # found
      if debug >2:                                                  # big debug=2
        logger.debug(f"  --> found: '{osib_link_obj}'")
      # normalize link_id
      if debug >2:                                                  # big debug=2
        logger.debug(f"    link_id(raw):        {link_id}")
      link_id  = '.'.join(map(str,link_id_path)).lower()            # update the link_id by the normalized path
      if debug >2:                                                  # big debug=2
        logger.debug(f"    link_id(normalized): {link_id}")
      # end normalize
      named_source_dict = _get_named_source(osib_link_obj, lang=lang, caller_function=caller_function)
      if (not is_empty_dict (named_source_dict)):
        if ('source' in named_source_dict) and (not is_empty(named_source_dict['source'])):   # link has a source
          link = named_source_dict['source']
        else:
          warn_str = f">>> runtime warning: osib_link(): 'link' is empty or not in yaml object '{link_id}' -> source: {named_source_dict}, language(s): {unique([lang, default_lang])}."
          logger.warning(warn_str)
          osib_warnings += 1
        if ('source_name' in named_source_dict) and (not is_empty(named_source_dict['source_name'])):         # link has a source_name
          link_name = named_source_dict['source_name']              # error handling if link_name is used and not overwritten, later
      # check for successor(s):
      if (latest > 0) and (_get_latest_links(osib_obj=osib_link_obj, latest_links=latest_links, lang=lang, caller_function=caller_function)):
        successor_str        = ""
        if len(latest_links) > 1:                                   # more than one successor: split_to
          if lang in split_to_texts:
            successor_str   += split_to_texts[lang]
          elif default_lang in split_to_texts:
            successor_str   += split_to_texts[default_lang]
          else:
            successor_str   += "split_to"
          successor_str   += " ["
          i = 1
          for successor_item in latest_links:
            if ('link' in successor_item):
              successor_id      = successor_item['link']
              successor_id_path = _get_path_list(path=successor_id, path_type="successor_id", caller_function=caller_function)
              if not is_empty_list(successor_id_path):
                successor_obj   = _lookup_yaml (osib_yaml, successor_id_path, 1)
                ### Mutate successor_item
                successor_item['link'] = '.'.join(map(str,successor_id_path)).lower()                   # update the link item by the normalized path
                if debug >2:                                        # big debug
                  logger.debug(f"    successor_item['link'](normalized): {successor_item['link']}")
                ### End Mutate
                named_source_dict = _get_named_source(successor_obj, lang=lang, caller_function=caller_function)
                successor_link  = ""
                successor_name  = ""
                if (not is_empty_dict (named_source_dict)):
                  if ('source' in named_source_dict) and (not is_empty(named_source_dict['source'])):   # link has a source
                    successor_link = named_source_dict['source']  # link has been verified in _get_latest_links
                  else:
                    warn_str = f">>> runtime warning: osib_link(): 'successor link' is empty or not in yaml object '{successor_id}'"
                    logger.warning(warn_str)
                    osib_warnings += 1
                  if (len(latest_links) <= 3):                        # add up to 3 successor names
                    if ('source_name' in named_source_dict) and (not is_empty(named_source_dict['source_name'])): # link has a source_name
                      successor_name = f": {named_source_dict['source_name']}"                           # error handling if link_name is used and not overwritten, later
                    else:
                      successor_name = f": {successor_link}"
                else:
                  warn_str = f">>> runtime warning: osib_link(): 'named successor link' is empty or not in yaml object '{successor_id}'"
                  logger.warning(warn_str)
                  osib_warnings += 1
                if i > 1:
                  successor_str  += separator
                successor_str  += f"[{str(i)}{successor_name}]({successor_link})"               # markdown link to successor
                i += 1
          successor_str += "]"
        elif len(latest_links) == 1:                                # one successor
          if latest_links and latest_links[0] and ('link' in latest_links[0]):
            successor_id        = latest_links[0]['link']
            successor_id_path   = _get_path_list(path=successor_id, path_type="successor_id", caller_function=caller_function)
            if not is_empty_list(successor_id_path):
              successor_obj     = _lookup_yaml (osib_yaml, successor_id_path, 1)
              ### Mutate latest_links; TBD: Check if this is needed or too much
              latest_links[0]['link'] = '.'.join(map(str,successor_id_path))                    # update the link item by the normalized path
              if debug >2:                                          # big debug
                logger.debug(f"    latest_links[0]['link'](normalized): {latest_links[0]['link']}")
              ### End Mutate
              named_source_dict = _get_named_source(successor_obj, lang=lang, caller_function=caller_function)
              successor_link = ""
              successor_name = ""
              if (not is_empty_dict (named_source_dict)):
                if ('source' in named_source_dict) and (not is_empty(named_source_dict['source'])):   # link has a source
                  successor_link = named_source_dict['source']  # link has been verified in _get_latest_links
                else:
                  warn_str = f">>> runtime warning: osib_link(): 'successor link' is empty or not in yaml object '{successor_id}'"
                  logger.warning(warn_str)
                  osib_warnings += 1
                if ('source_name' in named_source_dict) and (not is_empty(named_source_dict['source_name'])):  # link has a source_name
                  successor_name = named_source_dict['source_name'] # error handling if link_name is used and not overwritten, later
                else:
                  successor_name = successor_link
              else:
                warn_str = f">>> runtime warning: osib_link(): 'named successor link' is empty or not in yaml object '{successor_id}'"
                logger.warning(warn_str)
                osib_warnings += 1
            if (latest <= 2):                                       # get the latest links
              successor_str     = "["
              if lang in successor_texts:
                successor_str  += successor_texts[lang]
              elif default_lang in successor_texts:
                successor_str  += successor_texts[default_lang]
              else:
                successor_str  += "successor"
              successor_str    += f": {successor_name}"
              successor_str    += f"]({successor_link})"
            elif (latest > 2):                                      # show only the latest version
              successor_str     = ""
              link              = successor_link
              link_name         = successor_name
              logger.info(f"MACRO osib_link(): replace link to '{link_id}' by source url to successor '{successor_id}'")
        else:
          logger.warning(f"MACRO osib_link(): received no (valid) successors for {link_id}")
          osib_warnings += 1
      elif latest == 0:
        logger.debug(f"  --> latest=0: '{link_id}' has been not checked for successors")
      else:
        logger.debug(f"  --> found version is the latest: '{link_id}'")
      if not is_empty (text):                                       # predefined text as link_text
        logger.debug(f"  link text: {text}")
        if result_str and result_str != "":
          result_str += separator
        result_str += "[" + text + "](" + link +")"                 # link to source
      else:                                                         # compile link_text: <prefix><doc_str><link_name>
        if is_empty(link_name):
          warn_str = f">>> runtime warning: 'name' is empty or not in yaml object '{link_id}' -> source: {named_source_dict}, language(s): {unique([lang, default_lang])}. Using 'link_name' = '{link}' instead."
          logger.warning(warn_str)
          osib_warnings += 1
          if not is_empty(link):
            link_name = link
          else:
            link_name = (f"{text} (OSIB: &lt;{link_id}&gt;: 'name' and 'source' are not defined. Verify 'osib.yml' and/or '{{ osib_anchor(...) }}', please)")
        if not is_empty(link):
          result_str = "[" + prefix + doc_str + link_name + "](" + link +")"
        else:
          result_str = "MACRO osib_link(): " + prefix + doc_str + link_name
      if (latest <=1) and (not is_empty(successor_str)):            # do not add successors, 1: log only a warning
        warn_str = f">>> warning: '{link_id}' has successors: '{successor_str}', please check you linked osib objects or change parameter 'latest=2' or 3."
        logger.warning(warn_str)
        osib_warnings += 1
        successor_str = ""
      elif not is_empty(successor_str):
        result_str += f"{separator}{successor_str}"
#     Adds automatically the requested link bidirectionally, if 'osib' is an existing osib object
#     get 'osib' path
      if not is_empty(osib):
        if osib.endswith(".attributes.links"):                      # 'attributes.links' must not be included in the path
          warn_str = ">>> runtime error: osib_link(): Do not add '.attributes.links' to parameter 'osib=...'!"
          logger.warning(warn_str)
          osib_warnings += 1
        osib_path    = _get_path_list(path=osib, path_type="osib", caller_function=caller_function)
        if is_empty_list(osib_path):                                # was 'doc_path' (ERROR)
          err_str = ">>> error in MACRO osib_link(): add to path is no osib-path: '{osib}'."
          logger.warning(err_str)
          osib_warnings += 1
        else:
          osib_obj   = _lookup_yaml (osib_yaml, osib_path, 1)       # normalizes osib_path also to aliased children
          # Mutate args['osib']
          if debug > 2:                                             # big debug
            logger.debug(f"    args['osib'](raw):        {args['osib']}")
            logger.debug(f"    osib_path[] =             {osib_path}")
          osib = '.'.join(map(str,osib_path))                       # update the osib argument by the normalized path
          args['osib'] = osib
          if debug > 2:                                             # big debug
            logger.debug(f"    args['osib'](normalized): {args['osib']}")
          # End Mutate osib
          # update or add links
          if osib_obj and osib_obj != "":                           # found osib object
            if debug > 2:                                           # big debug
              logger.debug(f"  osib_obj={osib_obj}\n")
            osib_links = _lookup_yaml (osib_obj, ["attributes", "links"], 0, get_attributes = True, create = True, caller_function=caller_function)
            add_link_dict = {
              'link':        link_id.lower(),
              'type':        type,
              'status':      status,
              'reviewed':    reviewed,
              'change':      change_new
            }
            added_yaml_data += 1                                    # count added data to yaml
#           Add reverse links at least here to normalize add_link_dict by _add_reverse_links mutating this list attribute
            if (not no_reverse): ### TBD! check this in _add_reverse_links to normaize the link independently from adding a reverse link
              if _add_reverse_links(**args, links=[ add_link_dict ], caller_function=caller_function): # add one list element
                logger.info(f"MACRO osib_link(): -> added reverse links of {link_id}")
            ### End add reverse link
            ### Check if no link to link_id and type exists ###
            if not is_empty_list(osib_links):
              _merge_links(osib_links, [add_link_dict])
            else:                                                   # add new attribute 'links' list
              osib_obj['attributes'] = {
                  'links': [ add_link_dict ]                        # list with a dict as 1st element
              } # first list element
            logger.info(f"-> osib_link({osib}):\n- {yaml.dump(add_link_dict, sort_keys=False, indent=2, default_flow_style=False)}")
            if debug >1:                                            # debug
              logger.debug(f"  => links({osib}):\n{yaml.dump(osib_obj['attributes']['links'], sort_keys=False, indent=2, default_flow_style=False)}")
        # End 'if add_to_path[0]'
#     End osib
    else: # osib_obj
      warn_str = f">>> MACRO osib_link(): runtime error:  did not find yaml object '{link_id}'"
      logger.warning(warn_str)
      osib_warnings += 1
      return(f"MACRO osib_link(): {text} (unresolved OSIB: &lt;{link_id}&gt; Typo or missing definition with '{{ osib_anchor(...) }}' ) <!--- {warn_str} --->")
    logger.info (f"MACRO osib_link(): ==> {result_str}\n")
#   Output
    if (not silent):
      return(result_str)
    else:
      return("")
  # end osib_link()


#################################################################################################################################################
# on_post_build(env):                                                                                                                           #
#   Write YAML file if new or changed attributes are present at the mkdocs macro signal on_post_build                                           #
#   Post Build actions, see https://mkdocs-macros-plugin.readthedocs.io/en/latest/advanced/#solution-post-build-actions                         #
# (C) OWASP/The Top10-Team, 2021                                                                                                                #
#################################################################################################################################################
def on_post_build(env):
  "Post-build actions"

  global added_yaml_data
  global osib_warnings
  global datestamp
  logger.info (f"OSIB-MACRO (post-build): Call On Post Build Action: Write added/changed yaml data to dir '{export_dir}'.")
  logger.info (f" -> Number of runtime WARNINGs: {osib_warnings}.")
  osib_warnings         = 0                                         # reset counter
  if added_yaml_data >0:                                            # new data added
    # site_dir    = env.conf['site_dir']
    now                 = datetime.now()
    timestamp           = now.strftime("%Y%m%d-%H%M%S")
    datestamp           = int(now.strftime("%Y%m%d"))               # get datestamp a numeric value
    if not os.path.isdir(export_dir):
      logger.info(f"Create directory '{export_dir}').")
      os.mkdir(export_dir,mode = 0o755)
    file_name   = export_dir+"/osib_export_"+timestamp+".yml"
    if debug >3:                                                    # big debug
      logger.debug(f" -> DATA:\n{yaml.dump(osib_yaml, sort_keys=False, indent=2, default_flow_style=False)}\n\n")
    logger.info(f"Write OSIB-yaml file '{file_name}' including up to {added_yaml_data} new or changed attributes.")
    added_yaml_data     = 0                                         # reset counter
    with open(file_name, 'w') as fout:
      data = yaml.dump(osib_yaml, fout, sort_keys=False, indent=2, default_flow_style=False)
    added_yaml_data = 0                                             # reset counter for new data
