#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: A module for common used exception classes in the Python DynDNS application
"""
from __future__ import absolute_import


#------------------------------------------------------------------------------
class DynDnsError(Exception):
    """Base error for this module."""
    pass

#------------------------------------------------------------------------------
class ConfigNotFoundError(DynDnsError):
    '''The searched configuration parameter was not found.'''

    # -------------------------------------------------------------------------
    def __init__(self, cfg_name):
        self.cfg_name = cfg_name

    # -------------------------------------------------------------------------
    def __str__(self):
        return "The configuration parameter {!r} could not be found.".format(self.cfg_name)


#------------------------------------------------------------------------------
class UsernameExistsError(DynDnsError):
    '''The given username already exists with another user Id.'''

    # -------------------------------------------------------------------------
    def __init__(self, user_name):
        self.user_name = user_name

    # -------------------------------------------------------------------------
    def __str__(self):
        return "The user name {!r} already exists.".format(self.user_name)



#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
