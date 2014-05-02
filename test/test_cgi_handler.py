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
def restore_env(func):
    """
    Decorator function to restore all important environment variables
    """

    env_keys = (
        'DOCUMENT_ROOT',
        'GATEWAY_INTERFACE',
        'HTTP_ACCEPT',
        'HTTP_ACCEPT_ENCODING',
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_CONNECTION',
        'HTTP_HOST',
        'HTTP_USER_AGENT',
        'PATH',
        'QUERY_STRING',
        'REMOTE_ADDR',
        'REMOTE_PORT',
        'REQUEST_METHOD',
        'REQUEST_URI',
        'SCRIPT_FILENAME',
        'SCRIPT_NAME',
        'SERVER_ADDR',
        'SERVER_ADMIN',
        'SERVER_NAME',
        'SERVER_PORT',
        'SERVER_PROTOCOL',
        'SERVER_SIGNATURE',
        'SERVER_SOFTWARE',
        'UNIQUE_ID',
    )

    def caller(self, *args, **kwargs):

        old_env = {}
        for key in env_keys:
            old_env[key] = None
            if key in os.environ:
                old_env[key] = os.environ[key]
        #log.debug("Saved environment: %s", pp(old_env))

        try:
            return func(self, *args, **kwargs)
        finally:
            for key in env_keys:
                if key in old_env:
                    if old_env[key] is None:
                        if key in os.environ:
                            del os.environ[key]
                    else:
                        os.environ[key] = old_env[key]
                else:
                    if key in os.environ:
                        del os.environ[key]

    return caller

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

    #--------------------------------------------------------------------------
    @restore_env
    def test_is_cgi(self):

        log.info("Testing property 'is_cgi'.")

        from py_ddns.cgi_handler import CgiHandler

        os.environ['GATEWAY_INTERFACE'] = 'CGI/1.0'

        hdlr = CgiHandler(
                appname = self.appname,
                verbose = self.verbose,
        )
        self.assertTrue(hdlr.is_cgi)
        del hdlr

        del os.environ['GATEWAY_INTERFACE']

        hdlr = CgiHandler(
                appname = self.appname,
                verbose = self.verbose,
        )
        self.assertFalse(hdlr.is_cgi)
        del hdlr

    #--------------------------------------------------------------------------
    def test_charset(self):

        log.info("Testing properties 'charset' and 'islatin_charset'.")

        from py_ddns.cgi_handler import CgiHandler

        hdlr = CgiHandler(
                appname = self.appname,
                verbose = self.verbose,
        )

        cset_list = (
            None,
            'utf-8',
            ' utf-8 ',
            'ISO-8859-1',
            'iso-8859-1 ',
            'ISO-8859-15',
            'WINDOWS-1252',
        )

        csets = {
            None: (None, True),
            'utf-8': ('utf-8', False),
            ' utf-8 ': ('utf-8', False),
            'ISO-8859-1': ('ISO-8859-1', True),
            'iso-8859-1 ': ('iso-8859-1', True),
            'ISO-8859-15': ('ISO-8859-15', False),
            'WINDOWS-1252': ('WINDOWS-1252', True),
        }

        for cset in cset_list:
            log.debug("Testing character set %r ...", cset)
            exp_cset = csets[cset][0]
            is_latin = csets[cset][1]
            hdlr.charset = cset
            self.assertEqual(hdlr.charset, exp_cset)
            self.assertEqual(hdlr.islatin_charset, is_latin)

    #--------------------------------------------------------------------------
    @restore_env
    def test_escape_html(self):

        log.info("Testing escaping HTML entities.")

        from py_ddns.cgi_handler import CgiHandler

        test_strings = (
            ('<html>Me & you.</html>', '&lt;html&gt;Me &amp; you.&lt;/html&gt;'),
            ('\'bla\' "Sülz"', '\'bla\' &quot;Sülz&quot;'),
        )

        test_string_nl = (
            "first row.\n'Second' row.\r\nthird row.\r\n",
            'first row.&#10;&#39;Second&#39; row.&#13;&#10;third row.&#13;&#10;',
        )

        os.environ['GATEWAY_INTERFACE'] = 'CGI/1.0'

        hdlr = CgiHandler(
                appname = self.appname,
                verbose = self.verbose,
                charset = 'utf-8',
        )

        for test_str in test_strings:
            log.debug("Escaping entities in %r ...", test_str[0])
            escaped = hdlr.escape_html(test_str[0])
            exp = test_str[1]
            log.debug("Expected string %r: %r.", exp.__class__.__name__, exp)
            log.debug("Escaped string %r: %r.", escaped.__class__.__name__, escaped)
            self.assertEqual(exp, escaped,
                    ("Escaped string %r is not equal to %r." % (escaped, exp)))

        log.debug("Escaping entities in %r (UTF-8)...", test_string_nl[0])
        escaped = hdlr.escape_html(test_string_nl[0])
        exp = test_string_nl[0]
        log.debug("Expected string %r: %r.", exp.__class__.__name__, exp)
        log.debug("Escaped string %r: %r.", escaped.__class__.__name__, escaped)
        self.assertEqual(exp, escaped,
                ("Escaped string %r is not equal to %r." % (escaped, exp)))

        hdlr.charset = 'windows-1252'
        log.debug("Escaping entities in %r (WINDOWS-1252)...", test_string_nl[0])
        escaped = hdlr.escape_html(test_string_nl[0], newlinestoo = True)
        exp = test_string_nl[1]
        log.debug("Expected string %r: %r.", exp.__class__.__name__, exp)
        log.debug("Escaped string %r: %r.", escaped.__class__.__name__, escaped)
        self.assertEqual(exp, escaped,
                ("Escaped string %r is not equal to %r." % (escaped, exp)))

        del hdlr

    #--------------------------------------------------------------------------
    @restore_env
    def test_unescape_html(self):

        log.info("Testing unescaping HTML entities.")

        test_strings = (
            ('&lt;html&gt;Me &amp; you.&lt;/html&gt;', '<html>Me & you.</html>'),
            ('\'bla\' &quot;Sülz&quot;', '\'bla\' "Sülz"'),
            ("first row.\n'Second' row.\r\nthird row.\r\n",
                "first row.\n'Second' row.\r\nthird row.\r\n"),
            ('first row.&#10;&#39;Second&#39; row.&#13;&#10;third row.&#13;&#10;',
                "first row.\n'Second' row.\r\nthird row.\r\n"),
        )

        from py_ddns.cgi_handler import CgiHandler

        os.environ['GATEWAY_INTERFACE'] = 'CGI/1.0'

        hdlr = CgiHandler(
                appname = self.appname,
                verbose = self.verbose,
                charset = 'windows-1252',
        )

        for test_str in test_strings:
            escaped = test_str[0]
            expected = test_str[1]
            log.debug("Unescaping entities in %r ...", escaped)
            log.debug("Expected string %r: %r.", expected.__class__.__name__, expected)
            unescaped = hdlr.unescape_html(escaped)
            log.debug("Unescaped string %r: %r.", unescaped.__class__.__name__, unescaped)
            self.assertEqual(expected, unescaped,
                    ("Unescaped string %r is not equal to %r." % (unescaped, expected)))

        del hdlr
        

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
    suite.addTest(TestCgiHandler('test_is_cgi', verbose))
    suite.addTest(TestCgiHandler('test_charset', verbose))
    suite.addTest(TestCgiHandler('test_escape_html', verbose))
    suite.addTest(TestCgiHandler('test_unescape_html', verbose))

    runner = unittest.TextTestRunner(verbosity = verbose)

    result = runner.run(suite)

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
