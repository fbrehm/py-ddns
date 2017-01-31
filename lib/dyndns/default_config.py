#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: Module for default configuration classes
"""
from __future__ import absolute_import

# Standard modules

#------------------------------------------------------------------------------
class Configuration(object):
    DEBUG = False
    TESTING = False
    JSON_AS_ASCII = False
    DATABASE_URI = 'postgres://dyndns@localhost:5432/dyndns'

#------------------------------------------------------------------------------
class ProductionConfig(Configuration):
    TESTING = False

#------------------------------------------------------------------------------
class DevelopmentConfig(Configuration):
    DEBUG = True

#------------------------------------------------------------------------------
class TestingConfig(Configuration):
    TESTING = True

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
