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

# Third party modules
from flask import current_app

import sqlalchemy
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Own modules
from ..constants import BASE_DIR, CFG_DIR, LOGGING_CONFIG, DEFAULT_DYNDNS_CONFIG
from ..constants import STATIC_DIR, TEMPLATES_DIR

db_session = None

LOG = logging.getLogger(__name__)


#------------------------------------------------------------------------------
Base = declarative_base()


#------------------------------------------------------------------------------
def create_session():

    dsn = current_app.config['DATABASE_URI']
    LOG.info("Creating database session with DSN {!r} ...".format(dsn))

    global db_session

    engine = sqlalchemy.create_engine(dsn)
    db_session = scoped_session(
        sessionmaker(autocommit=False, autoflush=False, bind=engine))
    Base.query = db_session.query_property()


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
