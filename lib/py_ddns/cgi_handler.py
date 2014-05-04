#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2014 by Frank Brehm, Berlin
@summary: The module for a CGI handler object
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

# Own modules
import pb_base
from pb_base.common import pp

from pb_base.errors import PbError

from pb_base.object import PbBaseObjectError
from pb_base.object import PbBaseObject

log = logging.getLogger(__name__)

__version__ = '0.1.1'

#==============================================================================
class CgiError(PbBaseObjectError):
    """Base error class for all exceptions happened during
    execution this application"""
    pass

#==============================================================================
# A UTC class.

ZERO = datetime.timedelta(0)

class UTC(datetime.tzinfo):
    """UTC

    Optimized UTC implementation. It unpickles using the single module global
    instance defined beneath this class declaration.
    """
    zone = "UTC"

    _utcoffset = ZERO
    _dst = ZERO
    _tzname = zone

    def fromutc(self, dt):
        if dt.tzinfo is None:
            return self.localize(dt)
        return super(utc.__class__, self).fromutc(dt)

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO

    def localize(self, dt, is_dst=False):
        '''Convert naive time to local time'''
        if dt.tzinfo is not None:
            raise ValueError('Not naive datetime (tzinfo is already set)')
        return dt.replace(tzinfo=self)

    def normalize(self, dt, is_dst=False):
        '''Correct the timezone information on the given datetime'''
        if dt.tzinfo is self:
            return dt
        if dt.tzinfo is None:
            raise ValueError('Naive time - no tzinfo set')
        return dt.astimezone(self)

    def __repr__(self):
        return "<UTC>"

    def __str__(self):
        return "UTC"

utc = UTC()

#==============================================================================
class CgiHandler(PbBaseObject):
    """
    Class for CGI dependend operations.
    """

    # class variables
    crlf = '\015\012'

    nph = False
    """
    @cvar: usage of a non-parsing header
    @type: bool
    """

    re_islatin = re.compile(r'^(ISO-8859-1|WINDOWS-1252)$', re.IGNORECASE)

    dtd_public_identifier = ''

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

    re_escaped_html = re.compile(r"&([^\s&]*?);")
    re_dec_entity = re.compile(r"#(\d+)$")
    re_hex_entity = re.compile(r"#x([0-9a-f]+)$", re.IGNORECASE)

    re_header = re.compile(r'([^ \r\n\t=]+)=\"?(.+?)\"?$')
    re_charset = re.compile(r'\bcharset\b')

    re_int = re.compile(r'^\s*(\d+)')
    re_expire_diff = re.compile(r'([+-]?(?:\d+|\d*\.\d*))([smhdwMy])')

    re_unfold = re.compile(crlf + r'(\s)')
    re_has_linebreaks = re.compile(crlf + '|\015|\012')

    #--------------------------------------------------------------------------
    def __init__(self,
            appname = None,
            verbose = 0,
            version = __version__,
            base_dir = None,
            errors_to_stdout = False,
            initialized = False,
            simulate = False,
            headers_once = False,
            charset = 'utf-8',
            cache = False,
            ):
        """
        Initialisation of the CGI handler object.

        @raise CgiError: on a uncoverable error.

        @param appname: name of the current running application
        @type appname: str
        @param verbose: verbose level
        @type verbose: int
        @param version: the version string of the current object or application
        @type version: str
        @param base_dir: the base directory of all operations
        @type base_dir: str
        @param errors_to_stdout: a flag indicating, that error messages
                                 should pushed to STDOUT wrapped as a
                                 HTML document instead to STDERR.
        @type use_stderr: bool
        @param initialized: initialisation is complete after __init__()
                            of this object
        @type initialized: bool
        @param simulate: don't execute actions, only display them
        @type simulate: bool
        @param headers_once: suppress redundant HTTP headers
        @type headers_once: bool
        @param charset: the used character set
        @type charset: str
        @param cache: flag whether header() will produce the
                      no-cache Pragma directive.
        @type cache: bool

        @return: None
        """

        self._errors_to_stdout = bool(errors_to_stdout)
        """
        @ivar: a flag indicating, that error messages should pushed to
               STDOUT wrapped as a HTML document instead to STDERR.
        @type: bool
        """

        self._charset = str(charset).strip()
        """
        @ivar: the used character set
        @type: str
        """

        self._headers_once = bool(headers_once)
        self._header_printed = 0

        self._is_cgi = False
        if 'GATEWAY_INTERFACE' in os.environ:
            self._is_cgi = True

        self._cache = bool(cache)

        super(CgiHandler, self).__init__(
                appname = appname,
                verbose = verbose,
                version = version,
                base_dir = base_dir,
                use_stderr = True,
                initialized = False,
        )

        self._simulate = bool(simulate)
        """
        @ivar: don't execute actions, only display them
        @type: bool
        """

        self._path_info = None
        self._script_name = None

        self.initialized = initialized
        if self.verbose > 3:
            log.debug("Initialized.")

    #------------------------------------------------------------
    @property
    def simulate(self):
        """Simulation mode."""
        return self._simulate

    @simulate.setter
    def simulate(self, value):
        self._simulate = bool(value)

    #------------------------------------------------------------
    @property
    def headers_once(self):
        """Suppress redundant HTTP headers."""
        return self._headers_once

    @headers_once.setter
    def headers_once(self, value):
        self._headers_once = bool(value)

    #------------------------------------------------------------
    @property
    def header_printed(self):
        """How often was the HTTP header printed."""
        return self._header_printed

    #------------------------------------------------------------
    @property
    def errors_to_stdout(self):
        """A flag indicating, that error messages should pushed to
            STDOUT wrapped as a HTML document instead to STDERR."""
        return self._errors_to_stdout

    @errors_to_stdout.setter
    def errors_to_stdout(self, value):
        self._errors_to_stdout = bool(value)

    #------------------------------------------------------------
    @property
    def is_cgi(self):
        """Flag, that the current application is a real CGI application."""
        return self._is_cgi

    #------------------------------------------------------------
    @property
    def charset(self):
        """The used character set."""
        return self._charset

    @charset.setter
    def charset(self, value):
        if value is None:
            self._charset = None
        else:
            self._charset = str(value).strip()

    #------------------------------------------------------------
    @property
    def islatin_charset(self):
        """Is the current character set a latin charset?"""
        if self.charset is None:
            return True
        if self.re_islatin.search(self.charset):
            return True
        return False

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

        uri = None
        if self.request_uri is not None:
            uri = unquote(re.sub(r'\?.*', '', self.request_uri))

        if uri is not None and uri != (scriptname + pathinfo):
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

    #--------------------------------------------------------------------------
    def as_dict(self, short = False):
        """
        Transforms the elements of the object into a dict

        @param short: don't include local properties in resulting dict.
        @type short: bool

        @return: structure as dict
        @rtype:  dict
        """

        res = super(CgiHandler, self).as_dict(short = short)
        res['simulate'] = self.simulate
        res['errors_to_stdout'] = self.errors_to_stdout
        res['headers_once'] = self.headers_once
        res['header_printed'] = self.header_printed
        res['is_cgi'] = self.is_cgi
        res['charset'] = self.charset
        res['islatin_charset'] = self.islatin_charset
        res['crlf'] = "%r" % (self.crlf)
        res['cache'] = self.cache
        res['request_uri'] = self.request_uri
        res['name_and_path_from_env'] = self.name_and_path_from_env
        res['path_info'] = self.path_info
        res['script_name'] = self.script_name
        res['nph'] = self.nph

        return res

    #--------------------------------------------------------------------------
    def __repr__(self):
        """Typecasting into a string for reproduction."""

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("appname=%r" % (self.appname))
        fields.append("verbose=%r" % (self.verbose))
        fields.append("version=%r" % (self.version))
        fields.append("base_dir=%r" % (self.base_dir))
        fields.append("initialized=%r" % (self.initialized))
        fields.append("errors_to_stdout=%r" % (self.errors_to_stdout))
        fields.append("simulate=%r" % (self.simulate))
        fields.append("headers_once=%r" % (self.headers_once))
        fields.append("charset=%r" % (self.charset))
        fields.append("cache=%r" % (self.cache))

        out += ", ".join(fields) + ")>"
        return out

    #--------------------------------------------------------------------------
    def server_software(self):

        if 'SERVER_SOFTWARE' in os.environ and os.environ['SERVER_SOFTWARE']:
            return os.environ['SERVER_SOFTWARE']
        return 'cmdline'

    #--------------------------------------------------------------------------
    def escape_html(self, toencode, newlinestoo = False):
        """
        Escape HTML, e.g. '>' -> '&gt;'

        @param toencode: the string, where to escape entities
        @type toencode: str
        @param newlinestoo: escape also new line and carriage return characters
        @type newlinestoo: bool

        @return: the string with escaped entities
        @rtype: str

        """

        if toencode is None:
            return None

        toencode = self.re_amp_sign.sub('&amp;', toencode)
        toencode = self.re_lt_sign.sub('&lt;', toencode)
        toencode = self.re_gt_sign.sub('&gt;', toencode)

        if self.re_html_3_2.search(self.dtd_public_identifier):
            toencode = self.re_dquot_sign.sub('&#34;', toencode)
        else:
            toencode = self.re_dquot_sign.sub('&quot;', toencode)

        if self.charset and self.islatin_charset:
            toencode = self.re_squot_sign.sub('&#39;', toencode)
            toencode = self.re_hex_8b.sub('&#8249;', toencode)
            toencode = self.re_hex_9b.sub('&#8250;', toencode)
            if newlinestoo:
                toencode = self.re_oct_12.sub('&#10;', toencode)
                toencode = self.re_oct_15.sub('&#13;', toencode)

        return toencode

    #--------------------------------------------------------------------------
    def unescape_html(self, to_unescape):
        """
        Unescape HTML, e.g. '&lt;' -> '<'

        @param to_unescape: the character string, where to unescape entities
        @type to_unescape: str

        @return: the character string with unescaped entities
        @rtype: str

        """

        if to_unescape is None:
            return None

        latin = True
        if self.charset is not None:
            if not self.islatin_charset:
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
    def header(self, ctype = None, status = None, cookie = None,
            target = None, expires = None, nph = None, charset = None,
            others = None, **other_kws):
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

        if charset:
            charset = unfold(charset, "Charset")

        other_headers = []
        if isinstance(others, list) or isinstance(others, tuple):
            for c in others:
                hdr = unfold(c, "Other")
                match = self.re_header.search(hdr)
                if match:
                    hdr_name = match.group(1)
                    value = match.group(2)
                    hdr = (hdr_name[0:1].upper() + hdr_name[1:].lower() + ': ' +
                            self.unescape_html(value))
                other_headers.append(hdr)
        elif others:
            hdr = unfold(others, "Other")
            match = self.re_header.search(hdr)
            if match:
                hdr_name = match.group(1)
                value = match.group(2)
                hdr = (hdr_name[0:1].upper() + hdr_name[1:].lower() + ': ' +
                        self.unescape_html(value))
            other_headers.append(hdr)
        for key in other_kws:
            value = other_kws[key]
            hdr = (key[0:1].upper() + key[1:].lower() + ': ' +
                    self.unescape_html(value))
            hdr = unfold(hdr, 'Others')
            other_headers.append(hdr)

        # Normalize NPH
        if nph is not None:
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

        if expires is not None:
            headers.append("Expires: %s" % (
                    self.format_expire_date(expires, False)))
        if expires is not None or cookies or nph:
            headers.append("Date: %s" % (self.format_expire_date(0, False)))
        if self.cache:
            headers.append("Pragma: no-cache")
        for hdr in other_headers:
            headers.append(hdr[0:1].upper() + hdr[1:])
        if ctype:
            headers.append("Content-Type: %s" % (ctype))

        return self.crlf.join(headers) + self.crlf + self.crlf

    #--------------------------------------------------------------------------
    def format_expire_date(self, etime = None, format_cookie = False):
        """
        Creates date strings suitable for use in cookies and HTTP headers.
        (They differ, unfortunately.)

        @param etime: the time to format
                      possible given values are::
                        * None or 0 or 'now'    -- expire immediately
                        * an integer value > 0  -- an UNIX timestamp, when to expire
                        * "+180s"               -- in 180 seconds
                        * "+2m"                 -- in 2 minutes
                        * "+12h"                -- in 12 hours
                        * "+1d"                 -- in one day
                        * "+2w"                 -- in 2 weeks
                        * "+3M"                 -- in 3 months
                        * "+2y"                 -- in 2 years
                        * "-3m"                 -- 3 minutes ago(!)
        @type: None or int or str

        @return: the formatted Expire time
        @rtype: str

        """

        etime = self._calc_expire_date(etime)
        if not isinstance(etime, int):
            return str(etime)

        sc = ' '
        if format_cookie:
            sc = '-'

        (lang_code, encoding) = locale.getlocale(locale.LC_TIME)
        if lang_code:
            locale.setlocale(locale.LC_TIME, 'C')

        fmt = "%a, %d" + sc + "%b" + sc + "%Y %H:%M:%S GMT"
        try:
            dt = datetime.datetime.utcfromtimestamp(etime)
            dt_formatted = dt.strftime(fmt)
        finally:
            if lang_code:
                locale.setlocale(locale.LC_TIME, (lang_code, encoding))

        return dt_formatted

    #--------------------------------------------------------------------------
    def _calc_expire_date(self, etime = None):
        """
        Creates an expires time exactly some number of hours from the current time.
        """

        offset = 0
        mult = {
                's': 1,
                'm': 60,
                'h': 60 * 60,
                'd': 60 * 60 * 24,
                'w': 60 * 60 * 24 * 7,
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
        elif isinstance(etime, datetime.timedelta):
            dt = datetime.datetime.now() + etime
            return int(dt.strftime('%s'))
        elif isinstance(etime, datetime.datetime):
            return int(etime.strftime('%s'))
        elif isinstance(etime, datetime.date):
            dt = datetime.datetime(etime.year, etime.month, etime.day, tzinfo = utc)
            return int(dt.strftime('%s'))
        elif isinstance(etime, datetime.time):
            _today = datetime.date.today()
            dt = datetime.datetime(_today.year, _today.month, _today.day,
                    etime.hour, etime.minute, etime.second, etime.microsecond,
                    etime.tzinfo)
            if dt < datetime.datetime.now():
                dt += datetime.timedelta(1)
            return int(dt.strftime('%s'))
        elif not isinstance(etime, int):
            return etime

        if self.verbose > 3:
            log.debug("Offset is %d.", offset)
        return int(time.time()) + offset


#==============================================================================

if __name__ == "__main__":

    pass

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
