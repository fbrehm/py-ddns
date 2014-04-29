#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank.brehm@profitbricks.com
@organization: Profitbricks GmbH
@copyright: © 2010 - 2014 by Frank Brehm, Berlin
@license: GPL3
@summary: test script (and module) for unit tests on the CGI handler object
"""

import unittest
import os
import sys
import logging
import tempfile
import time
import locale

libdir = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', 'lib'))
sys.path.insert(0, libdir)

from pb_base.common import pp, to_unicode_or_bust, to_utf8_or_bust
from pb_base.common import bytes2human

import general
from general import DynDnsTestcase, get_arg_verbose, init_root_logger

locale.setlocale(locale.LC_ALL, '')

log = logging.getLogger(__name__)

#==============================================================================

class TestCgiHandler(DynDnsTestcase):

    #--------------------------------------------------------------------------
    def setUp(self):
        self.appname = 'test_cgi_handler'

    #--------------------------------------------------------------------------
    def tearDown(self):
        pass

    #--------------------------------------------------------------------------
    def test_import(self):

        if self.verbose > 2:
            log.debug("Import path: %r", sys.path)

        log.info("Testing import of py_ddns.cgi_handler ...")
        import py_ddns.cgi_handler

        log.info("Testing import of CgiError from pb_base.handler ...")
        from py_ddns.cgi_handler import CgiError

        log.info("Testing import of CgiHandler from pb_base.handler ...")
        from py_ddns.cgi_handler import CgiHandler

    #--------------------------------------------------------------------------
    def test_cgi_handler_object(self):

        log.info("Testing init of a cgi handler object.")

        from py_ddns.cgi_handler import CgiHandler

        hdlr = CgiHandler(
            appname = self.appname,
            verbose = self.verbose,
        )
        log.debug("CgiHandler %%r: %r", hdlr)
        log.debug("CgiHandler %%s: %s", str(hdlr))


#==============================================================================


if __name__ == '__main__':

    verbose = get_arg_verbose()
    if verbose is None:
        verbose = 0
    init_root_logger(verbose)

    log.info("Starting tests ...")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTest(TestCgiHandler('test_import', verbose))
    suite.addTest(TestCgiHandler('test_cgi_handler_object', verbose))

    runner = unittest.TextTestRunner(verbosity = verbose)

    result = runner.run(suite)

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
