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

# Own modules
from .constants import BASE_DIR, CFG_DIR, LOGGING_CONFIG, DEFAULT_DYNDNS_CONFIG
from .constants import STATIC_DIR, TEMPLATES_DIR

from .model_config import DB_CONFIG_FILE, DSN

from .views import api


# Constants

LOG = logging.getLogger("dyndns")

__author__ = 'Frank Brehm <frank@brehm-online.com>'
__copyright__ = '(C) 2010 - 2017 by Frank Brehm, Berlin'
__contact__ = 'frank.brehm@profitbricks.com'
__version__ = '0.2.1'
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


#------------------------------------------------------------------------------
def create_app():

    LOG.info("Configuring runtime ...")

    LOG.debug("Static folder is now %r.", STATIC_DIR)
    LOG.debug("Template folder is now %r.", TEMPLATES_DIR)

    LOG.info("Creating Flask application ...")
    app = Flask(__name__, static_folder=STATIC_DIR)

    # Update logger
    app.logger_name = "dashboard"

    # load default configuration
    LOG.info("Loading default dyndns config from {0}"
                .format(DEFAULT_DYNDNS_CONFIG))
    app.config.from_pyfile(DEFAULT_DYNDNS_CONFIG, silent=True)

    # overwrite with custom configuration path (via env)
    dyndns_config = os.environ.get('DYNDNS_CONFIG')
    LOG.debug("DYNDNS_CONFIG: {0!r}".format(dyndns_config))
    if dyndns_config:
        LOG.info("Loading dyndns config DYNDNS_CONFIG={0!r}"
                    .format(dyndns_config))
        app.config.from_envvar('DYNDNS_CONFIG')

    # register application parts
    LOG.info("Initializing blueprints ...")
    app.register_blueprint(api)
    LOG.info("Blueprints initialized")

    LOG.debug("Database configuration file: %r", DB_CONFIG_FILE)
    LOG.info("Log in to database: %r", DSN)
    LOG.info("Flask application created")

    return app



#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
