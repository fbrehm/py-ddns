#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2017 by Frank Brehm, Berlin
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

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
