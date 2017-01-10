#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2017 by Frank Brehm, Berlin
@summary: All modules for Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging
import logging.config
import json

# Third party modules

from flask import Flask

# Constants
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
CFG_DIR = os.path.join(BASE_DIR, 'conf')
LOGGING_CONFIG = os.path.join(CFG_DIR, "logging.json")

LOG = logging.getLogger("dyndns")

__author__ = 'Frank Brehm <frank@brehm-online.com>'
__copyright__ = '(C) 2010 - 2017 by Frank Brehm, Berlin'
__contact__ = 'frank.brehm@profitbricks.com'
__version__ = '0.1.0'
__license__ = 'LGPLv3+'

#------------------------------------------------------------------------------
def configure_logging():

    print("Configuring logging from file {0} ...".format(LOGGING_CONFIG))

    logging_config_json = {}

    with open(LOGGING_CONFIG) as logging_config_file:
        logging_config_json = json.load(logging_config_file)

    logging.basicConfig(level=logging.INFO)
    logging.config.dictConfig(logging_config_json)

    LOG.info('Logging configured ✓')



#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
