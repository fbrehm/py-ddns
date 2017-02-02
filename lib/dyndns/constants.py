#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: Most constants used in Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os

# Constants

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
CFG_DIR = os.path.join(BASE_DIR, 'conf')
LOGGING_CONFIG = os.path.join(CFG_DIR, "logging.json")
DEFAULT_DYNDNS_CONFIG = 'dyndns.cfg'
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

GLOBAL_CONFIG_DIR = os.sep + os.path.join("etc", "dyndns")
GLOBAL_CONFIG_FILE = os.path.join(GLOBAL_CONFIG_DIR, 'dyndns.json')
GLOBAL_LOGGING_CONFIG = os.path.join(GLOBAL_CONFIG_DIR, "logging.json")

CONFIG = {
    'default_user_max_hosts': {
        'type': 'int', 'default': 3,
        'description': 'Default value for maximal hosts for users.'},
    'passwd_restrict_min_len': {'type': 'int', 'default': 8},
    'passwd_restrict_small_chars_required': {'type': 'bool', 'default': True},
    'passwd_restrict_capitals_required': {'type': 'bool', 'default': True},
    'passwd_restrict_digits_required': {'type': 'bool', 'default': True},
    'passwd_restrict_special_chars_required': {'type': 'bool', 'default': True},
    'debug': {
        'type': 'bool', 'default': False,
        'description': 'If True, then enabling logging of all SQL statements.'},
    'model_version': {'type': 'version', 'default': '0.2.1'},
    'zzz_blub': {'type': 'str', 'default': 'Blah'},
}

LOGIN_REALM = "DynDNS Login Required"

DEFAULT_ADMIN_NAME = 'admin'
DEFAULT_ADMIN_PASSWD = 'password'

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
