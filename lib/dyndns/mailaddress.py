#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank.brehm@pixelpark.com
@copyright: © 2010 - 2016 by Frank Brehm, ProfitBricks GmbH, Berlin
@summary: The module for the MailAddress object.
"""

# Standard modules
import sys
import os
import logging
import re

# Own modules
from postfix_migration.errors import InvalidMailAddressError

from postfix_migration.common import to_str

__version__ = '0.2.1'
log = logging.getLogger(__name__)


# =============================================================================
class MailAddress(object):
    """
    Class for encapsulating a mail simple address.
    """

    pattern_valid_domain = r'@((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z][a-z]+)$'

    pattern_valid_user = r'^([a-z0-9][a-z0-9_\-\.\+\&@]*[a-z0-9]'
    pattern_valid_user += r'(?:\+[a-z0-9][a-z0-9_\-\.]*[a-z0-9])*)'

    pattern_valid_address = pattern_valid_user + pattern_valid_domain

    re_valid_user = re.compile(pattern_valid_user + r'$', re.IGNORECASE)
    re_valid_domain = re.compile(r'^' + pattern_valid_domain, re.IGNORECASE)
    re_valid_address = re.compile(pattern_valid_address, re.IGNORECASE)

    verbose = 0

    # -------------------------------------------------------------------------
    @classmethod
    def valid_address(cls, address, raise_on_failure=False):

        if not address:
            e = InvalidMailAddressError(address, "Empty address.")
            if raise_on_failure:
                raise e
            elif cls.verbose > 2:
                log.debug(str(e))
            return False

        addr = to_str(address)
        if not isinstance(addr, str):
            e = InvalidMailAddressError(address, "Wrong type.")
            if raise_on_failure:
                raise e
            elif cls.verbose > 2:
                log.debug(str(e))
            return False

        if cls.re_valid_address.search(addr):
            return True

        e = InvalidMailAddressError(address, "Invalid address.")
        if raise_on_failure:
            raise e
        elif cls.verbose > 2:
            log.debug(str(e))
        return False

    # -------------------------------------------------------------------------
    def __init__(self, user=None, domain=None):

        self._user = ''
        self._domain = ''

        if not domain:
            if user:
                addr = to_str(user)
                if self.valid_address(addr):
                    match = self.re_valid_address.search(addr)
                    self._user = match.group(1)
                    self._domain = match.group(2)
                    return
                match = self.re_valid_domain.search(addr)
                if match:
                    self._domain = match.group(1)
                    return
                self._user = addr
                return

        self._user = to_str(user)
        self._domain = to_str(domain)

    # -----------------------------------------------------------
    @property
    def user(self):
        """The user part of the address."""
        if self._user is None:
            return ''
        return self._user

    # -----------------------------------------------------------
    @property
    def domain(self):
        """The domain part of the address."""
        if self._domain is None:
            return ''
        return self._domain

    # -------------------------------------------------------------------------
    def __str__(self):

        if not self.user and not self.domain:
            return ''

        if not self.domain:
            return self.user

        if not self.user:
            return '@' + self.domain

        return self.user + '@' + self.domain

    # -------------------------------------------------------------------------
    def str_for_access(self):

        if not self.user and not self.domain:
            return None

        if not self.domain:
            return self.user + '@'

        if not self.user:
            return self.domain

        return self.user + '@' + self.domain

    # -------------------------------------------------------------------------
    def __repr__(self):
        """Typecasting into a string for reproduction."""

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("user=%r" % (self.user))
        fields.append("domain=%r" % (self.domain))

        out += ", ".join(fields) + ")>"
        return out


    # -------------------------------------------------------------------------
    def __hash__(self):
        return hash(str(self).lower())

    # -------------------------------------------------------------------------
    def __eq__(self, other):

        if not isinstance(other, MailAddress):
            if other is None:
                return False
            return str(self).lower() == str(other).lower()

        if not self.user:
            if other.user:
                return False
            if not self.domain:
                if other.domain:
                    return False
                return True
            if not other.domain:
                return False
            if self.domain.lower() == other.domain.lower():
                return True
            return False

        if not self.domain:
            if other.domain:
                return False
            if not other.user:
                return False
            if self.user.lower() == other.user.lower():
                return True
            return False

        if not other.user:
            return False
        if not other.domain:
            return False
        if self.domain.lower() != other.domain.lower():
            return False
        if self.user.lower() != other.user.lower():
            return False

        return True

    # -------------------------------------------------------------------------
    def __ne__(self, other):

        if self == other:
            return False
        return True

    # -------------------------------------------------------------------------
    def __lt__(self, other):

        if not isinstance(other, MailAddress):
            if other is None:
                return False
            return str(self).lower() < str(other).lower()

        if not self.user:
            if not self.domain:
                if other.domain:
                    return False
                return True
            if not other.domain:
                return False
            if self.domain.lower() != other.domain.lower():
                return self.domain.lower() < other.domain.lower()
            if other.user:
                return False
            return True

        if not self.domain:
            if other.domain:
                return True
            if not other.user:
                return False
            if self.user.lower() != other.user.lower():
                return self.user.lower() < other.user.lower()
            return False

        if not other.domain:
            return False
        if not other.user:
            return False

        if self.domain.lower() != other.domain.lower():
            return self.domain.lower() < other.domain.lower()
        if self.user.lower() != other.user.lower():
            return self.user.lower() < other.user.lower()

        return False

    # -------------------------------------------------------------------------
    def __gt__(self, other):

        if not isinstance(other, MailAddress):
            return NotImplemented

        if self < other:
            return False
        return True

    # -------------------------------------------------------------------------
    def __copy__(self):
        "Implementing a wrapper for copy.copy()."

        addr = MailAddress()
        addr._user = self.user
        addr._domain = self.domain
        return addr


# =============================================================================

if __name__ == "__main__":

    pass

# =============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 list
