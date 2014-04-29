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
class CgiHandler(PbBaseObject):
    """
    Class for CGI dependend operations.
    """

    # class variables
    crlf = '\015\012'

    re_islatin = re.compile(r'^(ISO-8859-1|WINDOWS-1252)$', re.IGNORECASE)

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



#==============================================================================

if __name__ == "__main__":

    pass

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
