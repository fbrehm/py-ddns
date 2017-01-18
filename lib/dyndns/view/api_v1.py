#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
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

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

# Own modules
from ..model import db_session

from . import api
from . import requires_auth
from . import gen_response

LOG = logging.getLogger(__name__)

api_version = '1.0'

#------------------------------------------------------------------------------
@api.route('/api/')
@api.route('/api/v1')
def api_root():
    LOG.info("Trying to get forbidden page {!r}.".format(request.path))
    abort(403)

#------------------------------------------------------------------------------
@api.route('/api/v1/status')
@requires_auth
def api_status():
    ctx = stack.top
    info = {
        'status': 'OK',
        'descr': 'All Batteries loaded.',
        'current_user': {
            'id': ctx.cur_user.user_id,
            'user_name': ctx.cur_user.user_name,
            'full_name': ctx.cur_user.full_name,
            'email': ctx.cur_user.email,
            'max_hosts': ctx.cur_user.max_hosts,
            'created': ctx.cur_user.created.isoformat(' '),
        }
    }
    if ctx.cur_user.is_admin:
        info['current_user']['is_admin'] = True
    return gen_response(info)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
