#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2014 by Frank Brehm, Berlin
@summary: The base module for a CGI app
"""

# Standard modules
import sys 
import os
import cgi
import cgitb
import logging
import time
import datetime

# Third party modules
import argparse

# Own modules
import pb_base
from pb_base.common import pp

from pb_base.errors import PbError

from pb_base.object import PbBaseObjectError

from pb_base.app import PbApplicationError

from pb_base.cfg_app import PbCfgAppError
from pb_base.cfg_app import PbCfgApp

__version__ = '0.1.0'

#==============================================================================
class CgiAppError(PbCfgAppError):
    """Base exception class for all CGI applications."""
    pass

#==============================================================================
class CgiApp(PbCfgApp):
    """Base class for all CGI applications."""

    #--------------------------------------------------------------------------
    # Class variables

    headers_once = False
    """
    @cvar: suppress redundant HTTP headers
    @type: bool
    """

    dtd_public_identifier = ''

    crlf = '\015\012'
    re_unfold = re.compile(crlf + r'(\s)')
    re_has_linebreaks = re.compile(crlf + '|\015|\012')
    re_int = re.compile(r'^\s*(\d+)')
    re_expire_diff = re.compile(r'([+-]?(?:\d+|\d*\.\d*))([smhdMy])')

    re_amp_sign = re.compile(r'&', re.DOTALL)
    re_lt_sign = re.compile(r'<', re.DOTALL)
    re_gt_sign = re.compile(r'>', re.DOTALL)
    re_dquot_sign = re.compile(r'"', re.DOTALL)
    re_squot_sign = re.compile(r"'", re.DOTALL)
    re_hex_8b = re.compile("\x8b", re.DOTALL)
    re_hex_9b = re.compile("\x9b", re.DOTALL)
    re_oct_12 = re.compile('\012', re.DOTALL)
    re_oct_15 = re.compile('\015', re.DOTALL)
    re_html_3_2 = re.compile(r'[^X]HTML 3\.2', re.IGNORECASE)

    re_islatin = re.compile(r'^(ISO-8859-1|WINDOWS-1252)$',
            re.IGNORECASE)

    nph = False

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
                cfg_stem = None,
                cfg_encoding = 'utf8',
                cfg_spec = None,
                need_config_file = False,
                ):
        """
        Initialisation of a base CGI application object.

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
        @param cfg_stem: the basename of the configuration file without any
                         file extension.
        @type cfg_stem: str
        @param cfg_encoding: encoding character set of the configuration files
                             must be a valid Python encoding
                             (See: http://docs.python.org/library/codecs.html#standard-encodings)
        @type cfg_encoding: str
        @param cfg_spec: Specification for configfile
        @type cfg_spec: str
        @param need_config_file: through an error message, if none of the default
                                 configuration files were found
        @type need_config_file: bool

        @return: None
        """

        self._is_cgi = False
        if 'GATEWAY_INTERFACE' in os.environ:
            self._is_cgi = True

        self._trace2stdout = False

        super(CgiApp, self).__init__(
                appname = appname,
                verbose = verbose,
                version = version,
                base_dir = base_dir,
                use_stderr = True,
                initialized = False,
                usage = usage,
                description = description,
                argparse_epilog = argparse_epilog,
                env_prefix = env_prefix,
                cfg_dir = cfg_dir,
                cfg_stem = cfg_stem,
                cfg_encoding = cfg_encoding,
                cfg_spec = cfg_spec,
                hide_default_config = True,
                need_config_file = False,
        )

        self._header_printed = 0
        self._charset = 'ISO-8859-1'

        self.cgi_form = cgi.FieldStorage()

    #------------------------------------------------------------
    @property
    def is_cgi(self):
        """Flag, that the current application is a real CGI application."""
        return self._is_cgi

    #------------------------------------------------------------
    @property
    def trace2stdout(self):
        """Flag showing, that all trace data should go to STDOUT."""
        return self._trace2stdout

    #------------------------------------------------------------
    @property
    def header_printed(self):
        """How often was the HTTP header printed."""
        return self._header_printed

    @header_printed.setter
    def header_printed(self, value):
        self._header_printed = int(value)

    #------------------------------------------------------------
    @property
    def charset(self):
        """The used charcter set."""
        return self._charset

    @charset.setter
    def charset(self, value):
        self._charset = str(value).strip()

    #------------------------------------------------------------
    @property
    def islatin(self):
        """Is the current character set a latin charset?"""
        if self.charset is None:
            return True
        if re_islatin.search(self.charset):
            return True
        return False

    #--------------------------------------------------------------------------
    def as_dict(self, short = False):
        """
        Transforms the elements of the object into a dict

        @param short: don't include local properties in resulting dict.
        @type short: bool

        @return: structure as dict
        @rtype:  dict
        """

        res = super(CgiApp, self).as_dict(short = short)
        res['is_cgi'] = self.is_cgi

        return res

    #--------------------------------------------------------------------------
    def init_logging(self):
        """
        Initialize the logger object.
        In a CGI environment it creates a simple logger to STDERR,
        else it performs the standard init_logging.

        @return: None
        """

        if not self.is_cgi:
            return super(CgiApp, self).init_logging()

        root_log = logging.getLogger()
        root_log.setLevel(logging.INFO)
        if self.verbose:
            root_log.setLevel(logging.DEBUG)

        # create formatter
        format_str = self.appname + ': '
        if self.verbose:
            if self.verbose > 1:
                format_str += '%(name)s(%(lineno)d) %(funcName)s() '
            else:
                format_str += '%(name)s '
        format_str += '%(levelname)s - %(message)s'
        formatter = logging.Formatter(format_str)

        # create log handler for console output
        lh_console = logging.StreamHandler(sys.stderr)
        if self.verbose:
            lh_console.setLevel(logging.DEBUG)
        else:
            lh_console.setLevel(logging.INFO)
        lh_console.setFormatter(formatter)

        root_log.addHandler(lh_console)

        return

    #--------------------------------------------------------------------------
    def header(self, ctype = None, status = None, cookie = None,
            target = None, expires = None, nph = None, charset = None, *others):
        """
        Return a Content-Type: style header
        """

        if self.header_printed:
            self.header_printed += 1
            if self.headers_once:
                return ''

        headers = []

        # Normalize cookies
        cookies = []
        if isinstance(cookie, list) or isinstance(cookie, tuple):
            for c in cookie:
                cookies.append(str(c))
        else:
            cookies.append(str(cookie))

        #--------------------------------
        # Unfolding
        def unfold(value, what):
            unfolded = self.re_unfold.sub(r'\1', value)
            if self.re_has_linebreaks.search(unfolded):
                msg = ("Invalid header value of %r contains a newline not " +
                        "followed by whitespace: %r") % (what, unfolded)
                raise ValueError(msg)
            return unfolded

        if ctype:
            ctype = unfold(ctype, "Content-type")

        if status:
            status = unfold(status, "Status")

        i = 0
        for c in cookies:
            cookies[i] = unfold(c, "Cookie")
            i += 1

        if target:
            target = unfold(target, "Target")

        if expires:
            expires = unfold(expires, "Expires")

        if nph:
            nph = unfold(nph, "NPH")

        if charset:
            charset = unfold(charset, "Target")

        i = 0
        for c in others:
            others[i] = unfold(c, "Other")
            i += 1

        # Normalize NPH
        if nph:
            nph = bool(nph)
        else:
            nph = self.nph

        # Default content type, if not given
        if not ctype:
            ctype = 'text/html'

        # Set charset, if given
        if charset:
            self.charset = charset
        charset = self.charset

    #--------------------------------------------------------------------------
    def escape_html(self, toencode, newlinestoo = False):
        """Escape HTML"""

        if toencode is None:
            return None

        toencode = re_amp_sign.sub('&amp;', toencode)
        toencode = re_lt_sign.sub('&lt;', toencode)
        toencode = re_gt_sign.sub('&gt;', toencode)

        if re_html_3_2.search(self.dtd_public_identifier):
            toencode = re_dquot_sign.sub('&#34;', toencode)
        else:
            toencode = re_dquot_sign.sub('&quot;', toencode)

        if self.charset and self.islatin:
            toencode = re_squot_sign.sub('&#39;', toencode)
            toencode = re_hex_8b.sub('&#8249;', toencode)
            toencode = re_hex_9b.sub('&#8250;', toencode)
            if newlinestoo:
                toencode = re_oct_12.sub('&#10;', toencode)
                toencode = re_oct_15.sub('&#13;', toencode)

        return toencode

    #--------------------------------------------------------------------------
    def unescape_html(self, to_unescape):
        """Unescape HTML"""

        if to_unescape is None:
            return None

        unescaped = to_unescape

        return unescaped

    #--------------------------------------------------------------------------
    def _calc_expire_date(self, etime = None):
        """
        Creates an expires time exactly some number of hours from the current time.

        format for etime can be in any of the forms...
        "now" -- expire immediately
        "+180s" -- in 180 seconds
        "+2m" -- in 2 minutes
        "+12h" -- in 12 hours
        "+1d"  -- in 1 day
        "+3M"  -- in 3 months
        "+2y"  -- in 2 years
        "-3m"  -- 3 minutes ago(!)

        """

        offset = 0
        mult = {
                's': 1,
                'm': 60,
                'h': 60 * 60,
                'd': 60 * 60 * 24,
                'M': 60 * 60 * 24 * 30,
                'y': 60 * 60 * 24 * 365,
        }

        if isinstance(etime, int):
            return etime

        if isinstance(etime, float):
            return int(etime)

        if etime is None:
            offset = 0
        elif isinstance(etime, str):
            match = re_int.search(etime)
            if match:
                return int(match.group(1))
            if etime.lower() == 'now':
                offset = 0
            else:
                match = re_expire_diff.search(etime)
                if match:
                    factor = 1.0
                    base = float(match.group(1))
                    unit = match.group(2)
                    if unit in mult:
                        factor = float(mult[unit])
                    offset = int(base * factor)
                else:
                    return etime
        else:
            return etime

        return time.time() + offset

    #--------------------------------------------------------------------------
#    def format_expire_date(self, etime = None):
#        """


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
