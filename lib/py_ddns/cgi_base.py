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
import re
import cgi
import cgitb
import logging
import time
import datetime
import locale

try:
    from urllib.parse import quote, unquote
except ImportError:
    from urllib import quote, unquote

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

log = logging.getLogger(__name__)

__version__ = '0.2.0'

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
    re_escaped_html = re.compile(r"&([^\s&]*?);")
    re_dec_entity = re.compile(r"#(\d+)$")
    re_hex_entity = re.compile(r"#x([0-9a-f]+)$", re.IGNORECASE)

    re_header = re.compile(r'([^ \r\n\t=]+)=\"?(.+?)\"?$')
    re_charset = re.compile(r'\bcharset\b')

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

        self._path_info = None
        self._script_name = None

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

        self._cache = False

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
    def cache(self):
        """
        Control whether header() will produce the no-cache Pragma directive.
        """
        return self._cache

    @cache.setter
    def cache(self, value):
        self._cache = bool(value)

    #------------------------------------------------------------
    @property
    def request_uri(self):
        """The literal request URI."""
        if 'REQUEST_URI' in os.environ and os.environ['REQUEST_URI']:
            return os.environ['REQUEST_URI']
        return None

    #------------------------------------------------------------
    @property
    def name_and_path_from_env(self):
        """Script name and path how given from environment."""

        scriptname = ''
        if 'SCRIPT_NAME' in os.environ and os.environ['SCRIPT_NAME']:
            scriptname = os.environ['SCRIPT_NAME']

        pathinfo = ''
        if 'PATH_INFO' in os.environ and os.environ['PATH_INFO']:
            pathinfo = os.environ['PATH_INFO']

        uri = unquote(re.sub(r'\?.*', '', self.request_uri))

        if uri != (scriptname + pathinfo):
            re_escaped_slash = re.compile(r'(?:\\/)+')
            script_name_pattern = re.escape(scriptname)
            script_name_pattern = re_escaped_slash.sub('/+', script_name_pattern)
            path_info_pattern = re.escape(pathinfo)
            path_info_pattern = re_escaped_slash.sub('/+', path_info_pattern)

            script_pattern = (r'^(' + script_name_pattern + ')(' +
                    path_info_pattern + ')$')
            match = re.search(script_pattern, uri, re.DOTALL)
            if match:
                scriptname = match.group(1)
                pathinfo = match.group(2)

        return (scriptname, pathinfo)

    #------------------------------------------------------------
    @property
    def path_info(self):
        """
        The extra virtual path information provided after the URL (if any).
        """
        if self._path_info is None:
            (scriptname, pathinfo) = self.name_and_path_from_env
            self._path_info = pathinfo
        return self._path_info

    @path_info.setter
    def path_info(self, value):
        if value is None:
            value = ''
        else:
            value = str(value)
        if value != '' and not value.startswith('/'):
            value = "/" + value
        self._path_info = value

    #------------------------------------------------------------
    @property
    def script_name(self):
        """
        The extra virtual path information provided after the URL (if any).
        """
        if self._script_name is None:
            (scriptname, pathinfo) = self.name_and_path_from_env
            self._script_name = scriptname
        return self._script_name

    @script_name.setter
    def script_name(self, value):
        if value is None:
            v = ''
        elif isinstance(value, (list, tuple)):
            if len(value) > 0:
                v = str(value.pop(0))
            else:
                v = ''
        else:
            v = str(value)
        self._script_name = v

    #------------------------------------------------------------
    @property
    def islatin(self):
        """Is the current character set a latin charset?"""
        if self.charset is None:
            return True
        if self.re_islatin.search(self.charset):
            return True
        return False

    #--------------------------------------------------------------------------
    def server_software(self):

        if 'SERVER_SOFTWARE' in os.environ and os.environ['SERVER_SOFTWARE']:
            return os.environ['SERVER_SOFTWARE']
        return 'cmdline'

    #--------------------------------------------------------------------------
    def escape_url(self, value):

        return quote(value)

    #--------------------------------------------------------------------------
    def unescape_url(self, value):

        return unquote(value)

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
        res['header_printed'] = self.header_printed
        res['charset'] = self.charset
        res['headers_once'] = self.headers_once
        res['dtd_public_identifier'] = self.dtd_public_identifier
        res['nph'] = self.nph

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
        elif cookie:
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

        # Check parameters
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
            hdr = unfold(c, "Other")
            match = self.re_header.search(hdr)
            if match:
                hdr_name = match.group(1)
                value = match.group(2)
                hdr = (hdr_name[0:1].upper() + hdr_name[1:].lower() + ': ' +
                        self.unescape_html(value))
            others[i] = hdr
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

        if ctype and (not self.re_charset.search(ctype)) and charset:
            ctype += "; charset=%s" % (charset)

        protocol = 'HTTP/1.0'
        if 'SERVER_PROTOCOL' in os.environ and os.environ['SERVER_PROTOCOL']:
            protocol = os.environ['SERVER_PROTOCOL']

        if nph:
            nph_status = '200 OK'
            if status:
                nph_status = status
            headers.append("%s %s" % (protocol, nph_status))
            headers.append("Server: %s" % (self.server_software()))

        if status:
            headers.append("Status: %s" % (status))
        if target:
            headers.append("Window-Target: %s" % (target))

        if cookies:
            for c in cookies:
                headers.append("Set-Cookie: %s" % (c))

        if expires:
            headers.append("Expires: %s" % (
                    self.format_expire_date(expires, False)))
        if expires or cookies or nph:
            headers.append("Date: %s" % (self.format_expire_date(0, False)))
        if self.cache:
            headers.append("Pragma: no-cache")
        for hdr in others:
            headers.append(hdr[0:1].upper() + hdr[1:])
        if ctype:
            headers.append("Content-Type: %s" % (ctype))

        return self.crlf.join(headers) + self.crlf + self.crlf

    #--------------------------------------------------------------------------
    def redirect(self, url, target = None, status = None, cookie = None,
            nph = None, *other):
        """
        Return a Location: style header
        """

        if not status:
            status = '302 Found'


    #--------------------------------------------------------------------------
    def utf8_chr(self, c):
        """
        Transforms the given integer value to the the appropriate character.

        @param c: the character value to transform
        @type c: int

        @return: the transformed character
        @rtype: str

        """

        c_value = int(c)
        if sys.version_info[0] > 2:
            char = chr(c_value)
        else:
            char = unichr(c_value).encode('utf-8')

        return char

    #--------------------------------------------------------------------------
    def url(self, absolute = False, relative = False, full = False,
            pathinfo = False, query = False, base = False, rewrite = None):
        """
        Returns the script's URL in a variety of formats.  Called without any
        arguments, it returns the full form of the URL, including host name
        and port number::

            http://your.host.com/path/to/script.cgi

        @param absolute: If true, produce an absolute URL, e.g.::
                            /path/to/script.cgi
        @type absolute: bool

        """

        _url = ''

        if base or not (absolute or relative):
            full = True
        if rewrite is None:
            rewrite = True

        path = self.path_info
        script_name = self.script_name
        request_uri = ''
        if self.request_uri:
            request_uri = unquote(self.request_uri)
        query_str = self.query_str

    #--------------------------------------------------------------------------
    def escape_html(self, toencode, newlinestoo = False):
        """Escape HTML"""

        if toencode is None:
            return None

        toencode = self.re_amp_sign.sub('&amp;', toencode)
        toencode = self.re_lt_sign.sub('&lt;', toencode)
        toencode = self.re_gt_sign.sub('&gt;', toencode)

        if self.re_html_3_2.search(self.dtd_public_identifier):
            toencode = self.re_dquot_sign.sub('&#34;', toencode)
        else:
            toencode = self.re_dquot_sign.sub('&quot;', toencode)

        if self.charset and self.islatin:
            toencode = self.re_squot_sign.sub('&#39;', toencode)
            toencode = self.re_hex_8b.sub('&#8249;', toencode)
            toencode = self.re_hex_9b.sub('&#8250;', toencode)
            if newlinestoo:
                toencode = self.re_oct_12.sub('&#10;', toencode)
                toencode = self.re_oct_15.sub('&#13;', toencode)

        return toencode

    #--------------------------------------------------------------------------
    def unescape_html(self, to_unescape):
        """Unescape HTML"""

        if to_unescape is None:
            return None

        latin = True
        if self.charset is not None:
            if not self.islatin:
                latin = False

        #-----------------
        def unescaped_char(matchobj):

            c = matchobj.group(1)

            if c == 'amp':
                return '&'

            if c == 'quot':
                return '"'

            if c == 'gt':
                return '>'

            if c == 'lt':
                return '<'

            if latin:

                ent_match = self.re_dec_entity.search(c)
                if ent_match:
                    number = int(ent_match.group(1))
                    return chr(number)

                ent_match = self.re_hex_entity.search(c)
                if ent_match:
                    number = int(ent_match.group(1), 16)
                    return chr(number)

            return '&%s;' % (c)

        unescaped = self.re_escaped_html.sub(unescaped_char, to_unescape)

        return unescaped

    #--------------------------------------------------------------------------
    def format_expire_date(self, etime = None, format_cookie = False):
        """
        Creates date strings suitable for use in cookies and HTTP headers.
        (They differ, unfortunately.)
        """

        etime = self._calc_expire_date(etime)
        if not isinstance(etime, int):
            return etime

        sc = ' '
        if format_cookie:
            sc = '-'

        dt = datetime.datetime.utcfromtimestamp(etime)

        (lang_code, encoding) = locale.getlocale(locale.LC_TIME)
        if lang_code:
            locale.setlocale(locale.LC_TIME, 'C')

        fmt = "%a, %d" + sc + "%b" + sc + "%Y %H:%M:%S GMT"
        dt_formatted = dt.strftime(fmt)
        if lang_code:
            locale.setlocale(locale.LC_TIME, (lang_code, encoding))
        return dt_formatted

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

        if self.verbose > 3:
            log.debug("Calculating expire date from %r", etime)

        if isinstance(etime, int) and etime != 0:
            if self.verbose > 3:
                log.debug("Returning %r", etime)
            return etime

        if isinstance(etime, float):
            if self.verbose > 3:
                log.debug("Returning %r", int(etime))
            return int(etime)

        if etime is None:
            offset = 0
        elif isinstance(etime, str):
            match = self.re_int.search(etime)
            if match:
                res = int(match.group(1))
                if self.verbose > 3:
                    log.debug("Returning %r", res)
                return res
            if etime.lower() == 'now':
                offset = 0
            else:
                match = self.re_expire_diff.search(etime)
                if match:
                    factor = 1.0
                    base = float(match.group(1))
                    unit = match.group(2)
                    if unit in mult:
                        factor = float(mult[unit])
                    offset = int(base * factor)
                else:
                    if self.verbose > 3:
                        log.debug("Returning %r", etime)
                    return etime
        elif not isinstance(etime, int):
            return etime

        if self.verbose > 3:
            log.debug("Offset is %d.", offset)
        return int(time.time()) + offset

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
