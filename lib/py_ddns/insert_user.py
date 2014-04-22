#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2014 by Frank Brehm, Berlin
@summary: The module insert_user CGI app
"""

# Standard modules
import sys 
import os
import cgi
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

from py_ddns.dyndns_app import DynDnsAppError
from py_ddns.dyndns_app import DynDnsApp

__version__ = '0.1.0'


#==============================================================================
class DynDnsInsertUserApp(DynDnsApp):

    def __init__(self):

        super(DynDnsInsertUserApp, self).__init__(
                appname = 'insert_user',
                initialized = False,
        )

        self.nph = True
        self.charset = 'UTF-8'
        self.post_init()

    def __call__(self):

        sys.stdout.write(self.header())
        sys.stdout.flush()
        #cgi.print_environ()


#==============================================================================

if __name__ == "__main__":

    pass

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
