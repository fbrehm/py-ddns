#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2014 by Frank Brehm, Berlin
@summary: The base module for all DynDNS applications
"""

# Standard modules
import sys 
import os
import cgi
import cgitb
import logging

# Third party modules

# Own modules
import pb_base
from pb_base.common import pp

from pb_base.errors import PbError

from pb_base.object import PbBaseObjectError

from pb_base.app import PbApplicationError

from pb_base.cfg_app import PbCfgAppError

from py_ddns.cgi_base import CgiAppError
from py_ddns.cgi_base import CgiApp

try:
    import py_ddns.local_version as my_version
except ImportError:
    import py_ddns.global_version as my_version

__version__ = '0.1.0'

#==============================================================================
class DynDnsAppError(CgiAppError):
    """Base exception class for all DynDns applications."""
    pass

#==============================================================================
class DynDnsApp(CgiApp):
    """Base class for all DynDns applications."""

    #--------------------------------------------------------------------------
    def __init__(self,
                appname = None,
                verbose = 0,
                version = __version__,
                base_dir = None,
                initialized = False,
                usage = None,
                description = None,
                argparse_epilog = None,
                env_prefix = None,
                cfg_dir = None,
                ):
        """
        Initialisation of a base DynDns application object.

        @raise CgiAppError: on a uncoverable error.

        @param appname: name of the current running application
        @type appname: str
        @param verbose: verbose level
        @type verbose: int
        @param version: the version string of the current object or application
        @type version: str
        @param base_dir: the base directory of all operations
        @type base_dir: str
        @param initialized: initialisation is complete after __init__()
                            of this object
        @type initialized: bool
        @param usage: usage text used on argparse (if called from
                      command line and not from CGI).
        @type usage: str
        @param description: a short text describing the application
        @type description: str
        @param argparse_epilog: an epilog displayed at the end
                                of the argparse help screen (if called
                                from command line and not from CGI).
        @type argparse_epilog: str
        @param env_prefix: a prefix for environment variables to find them
                           and assign them to the current application,
                           if not given, the appname in uppercase letters
                           and a trailing underscore is assumed.
        @type env_prefix: str
        @param cfg_dir: directory name under /etc or $HOME respectively, where the
                        normal configuration file should be located.
                        It defaults to self.appname.
                        If no seperate configuration dir should used, give an
                        empty string ('') as directory name.
        @type cfg_dir: str

        @return: None
        """

        if not cfg_dir:
            cfg_dir = 'dyndns'

        super(DynDnsApp, self).__init__(
                appname = appname,
                verbose = verbose,
                version = version,
                base_dir = base_dir,
                initialized = False,
                usage = usage,
                description = description,
                argparse_epilog = argparse_epilog,
                env_prefix = env_prefix,
                cfg_dir = cfg_dir,
                cfg_stem = 'dyndns',
                cfg_encoding = 'utf8',
                need_config_file = False,
        )




        if initialized:
            self.initialized = True

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
