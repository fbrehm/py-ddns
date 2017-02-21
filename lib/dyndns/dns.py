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

# Own modules

__version__ = '0.1.0'
LOG = logging.getLogger(__name__)


# =============================================================================
class Zone(object):
    """
    Class for encapsulating a managed zone.
    """

    verbose = 0

    # -------------------------------------------------------------------------
    def __init__(self, name, master_ns=None):

        self._name = name
        self._master_ns = master_ns

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




# =============================================================================

if __name__ == "__main__":

    pass

# =============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4 list
