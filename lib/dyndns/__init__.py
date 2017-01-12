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
from .constants import STATIC_DIR, TEMPLATES_DIR, GLOBAL_CONFIG_FILE, GLOBAL_LOGGING_CONFIG

from .model import create_session

from .views import api

from .tools import pp, to_bool

# Constants

LOG = logging.getLogger("dyndns")

__author__ = 'Frank Brehm <frank@brehm-online.com>'
__copyright__ = '(C) 2010 - 2017 by Frank Brehm, Berlin'
__contact__ = 'frank.brehm@profitbricks.com'
__version__ = '0.3.1'
__license__ = 'LGPLv3+'


#------------------------------------------------------------------------------
def configure_logging():

    print("Configuring logging from file {0} ...".format(LOGGING_CONFIG))

    logging_config_json = {}

    # Loading default logging configuration
    with open(LOGGING_CONFIG) as logging_config_file:
        logging_config_json = json.load(logging_config_file)

    # Loading logging configuration from /etc/dyndns/logging.json
    if os.path.exists(GLOBAL_LOGGING_CONFIG):
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
    app.logger_name = "dyndns"

    # load default configuration
    def_conf_class = 'dyndns.default_config.ProductionConfig'
    env = 'prod'
    env_keys = ('DYNDNS_ENVIRONMENT', 'DYNDNS_ENV')
    for key in env_keys:
        if key in os.environ:
            oenv = os.environ[key].lower()
            if oenv == 'test' or oenv == 'testing':
                env = 'test'
                break
            elif oenv == 'developing' or oenv == 'develop' or oenv == 'dev':
                env = 'dev'
                break
    if env == 'test':
        def_conf_class = 'dyndns.default_config.TestingConfig'
    elif env == 'dev':
        def_conf_class = 'dyndns.default_config.DevelopmentConfig'
    LOG.debug("Default configuration class: {0!r}".format(def_conf_class))
    app.config.from_object(def_conf_class)

    # overwrite with custom configuration from /etc/dyndns/dyndns.json
    if os.path.exists(GLOBAL_CONFIG_FILE):
        LOG.info("Loading dyndns config from file {0!r}".format(
                GLOBAL_CONFIG_FILE))
        app.config.from_json(GLOBAL_CONFIG_FILE)

    # overwrite with custom configuration path (via env)
    dyndns_config = os.environ.get('DYNDNS_CONFIG')
    LOG.debug("DYNDNS_CONFIG: {0!r}".format(dyndns_config))
    if dyndns_config:
        LOG.info("Loading dyndns config DYNDNS_CONFIG={0!r}"
                    .format(dyndns_config))
        app.config.from_envvar('DYNDNS_CONFIG', silent=True)

    LOG.debug("Using configuration:\n{}".format(pp(app.config)))

    # register application parts
    LOG.info("Initializing blueprints ...")
    app.register_blueprint(api)
    LOG.info("Blueprints initialized")

    with app.app_context():
        create_session()
    LOG.info("Flask application created")

    return app



#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
