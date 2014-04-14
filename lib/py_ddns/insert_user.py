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

# Third party modules

# Own modules


__version__ = '0.1.0'


#==============================================================================
class DynDnsInsertUserApp(object):

    def __init__(self):
        self.verbose = 2

    def __call__(self):

        print("Content-Type: text/plain")
        cgi.print_environ()


#==============================================================================

if __name__ == "__main__":

    pass

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
