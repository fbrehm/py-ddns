#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2017 by Frank Brehm, Berlin
@summary: All modules for Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging

# Third party modules

from flask import current_app
from flask import jsonify
from flask import request
from flask import abort

# Own modules
from .model import db_session
from .views import api

LOG = logging.getLogger(__name__)

api_version = '1.0'

#------------------------------------------------------------------------------
@api.route('/api/')
@api.route('/api/v1')
def api_root():
    LOG.info("Trying to get forbidden page {!r}.".format(request.path))
    abort(403)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
