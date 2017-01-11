#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2017 by Frank Brehm, Berlin
@summary: Module for default configuration classes
"""
from __future__ import absolute_import

# Standard modules

#------------------------------------------------------------------------------
class Config(object):
    DEBUG = False
    TESTING = False
    JSON_AS_ASCII = False
    DATABASE_URI = 'postgres://dyndns@localhost:5432/dyndns'

#------------------------------------------------------------------------------
class ProductionConfig(Config):
    TESTING = False

#------------------------------------------------------------------------------
class DevelopmentConfig(Config):
    DEBUG = True

#------------------------------------------------------------------------------
class TestingConfig(Config):
    TESTING = True

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
