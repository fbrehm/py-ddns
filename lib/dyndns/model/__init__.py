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

# Third party modules
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# Own modules
from ..constants import BASE_DIR, CFG_DIR, LOGGING_CONFIG, DEFAULT_DYNDNS_CONFIG
from ..constants import STATIC_DIR, TEMPLATES_DIR

from ..model_config import DB_CONFIG_FILE, DSN


engine = sqlalchemy.create_engine(DSN)

Session = sessionmaker(bind=engine)
db_session = Session()

Base = declarative_base()


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
