#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank.brehm@pixelpark.com
@copyright: © 2010 - 2017 by Frank Brehm, ProfitBricks GmbH, Berlin
@summary: The module for all DNS related things
"""

# Standard modules
import sys
import os
import logging
import re

# Third party modules
import dns.resolver

from dns.resolver import NoAnswer, NXDOMAIN
from dns.name import Name

# Own modules
from .tools import pp

__version__ = '0.3.0'
LOG = logging.getLogger(__name__)


# =============================================================================
class DnsZone(object):
    """
    Class for encapsulating a managed zone.
    """

    verbose = 0
    root_zone = Name(('', ))

    # -------------------------------------------------------------------------
    def __init__(self, name, master_ns=None, key_name=None, key_value=None):

        self._name = name
        self._master_ns = master_ns
        self._key_name = key_name
        self._key_value = key_value

    # -----------------------------------------------------------
    @property
    def name(self):
        """The name of the zone."""
        return self._name

    # -----------------------------------------------------------
    @property
    def master_ns(self):
        """The primary (master) nameserver of the zone."""
        return self._master_ns

    # -----------------------------------------------------------
    @property
    def key_name(self):
        """The name of the TSIG key for updating the zone."""
        return self._key_name

    # -----------------------------------------------------------
    @property
    def key_value(self):
        """The value of the TSIG key for updating the zone."""
        return self._key_value

    # -------------------------------------------------------------------------
    def __str__(self):
        """
        Typecasting function for translating object structure
        into a string

        @return: structure as string
        @rtype:  str
        """

        return pp(self.as_dict())

    # -------------------------------------------------------------------------
    def __repr__(self):
        """Typecasting into a string for reproduction."""

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("name={!r}".format(self.name))
        fields.append("master_ns={!r}".format(self.master_ns))
        fields.append("key_name={!r}".format(self.key_name))
        fields.append("key_value={!r}".format(self.key_value))

        out += ", ".join(fields) + ")>"
        return out

    # -------------------------------------------------------------------------
    def as_dict(self):
        """
        Transforms the elements of the object into a dict

        :return: structure as dict
        :rtype:  dict
        """

        res = self.__dict__
        res = {}
        for key in self.__dict__:
            if key.startswith('_') and not key.startswith('__'):
                continue
            val = self.__dict__[key]
            res[key] = val
        res['__class_name__'] = self.__class__.__name__
        res['name'] = self.name
        res['master_ns'] = self.master_ns
        res['key_name'] = self.key_name
        res['key_value'] = self.key_value
        res['version'] = __version__
        res['verbose'] = self.verbose

        return res

    # -------------------------------------------------------------------------
    def get_soa(self):
        """Returns the SOA record (Start of authority) for this zone."""

        LOG.debug("Trying to get SOA for zone {!r} ...".format(self.name))
        answers = dns.resolver.query(self.name, 'SOA')
        return answers[0]

    # -------------------------------------------------------------------------
    def check_usable(self):

        try:
            soa = self.get_soa()
        except NXDOMAIN as e:
            msg = "Zone {z!r} does not exists: {e}".format(z=self.name, e=e)
            return [msg]
        except NoAnswer as e:
            msg = "Got no SOA record for zone {!r}.".format(self.name)
            return [msg]
        LOG.debug("Got SOA for zone {z!r}: {s}".format(
            z=self.name, s=soa.to_text(origin=self.root_zone)))

        return []

# =============================================================================

if __name__ == "__main__":

    pass

# =============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 list
