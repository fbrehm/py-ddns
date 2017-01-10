#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2017 by Frank Brehm, Berlin
@summary: Module for model configuration
"""
from __future__ import absolute_import

# Standard modules
import os
import logging
import logging.config
import json
import sys

# Third party modules

# Own modules

from . import BASE_DIR, CFG_DIR
from .tools import to_str

# Constants
DB_CONFIG_FILE = os.path.join(CFG_DIR, 'db.json')


#------------------------------------------------------------------------------
class DbConfigurationError(Exception):
    pass


#------------------------------------------------------------------------------
DATABASE = {}

if not os.path.exists(DB_CONFIG_FILE):
    msg = "Database configuration file %r does not exists." % (DB_CONFIG_FILE)
    raise DbConfigurationError(msg)

if not os.path.isfile(DB_CONFIG_FILE):
    msg = "Database configuration file %r is not a regular file." % (DB_CONFIG_FILE)
    raise DbConfigurationError(msg)

if not os.access(DB_CONFIG_FILE, os.R_OK):
    msg = "No read access to database configuration file %r." % (DB_CONFIG_FILE)
    raise DbConfigurationError(msg)

try:
    with open(DB_CONFIG_FILE) as cfg_fh:
        DATABASE = json.load(cfg_fh)
except Exception as e:
    msg = "%s on reading database configuration file %r: %s\n\n" % (
        e.__class__.__name__, DB_CONFIG_FILE, e)
    sys.stderr.write(msg)
    raise

#DSN = to_str('%(drivername)s://%(username)s:%(password)s@%(host)s:%(port)d/%(database)s' % DATABASE)
DSN = to_str('%(drivername)s://%(username)s@%(host)s:%(port)d/%(database)s' % DATABASE)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
