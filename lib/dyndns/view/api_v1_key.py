#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: A module for TSIG keys dependend routes in the Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging
import crypt
import re

# Third party modules

from flask import current_app
from flask import jsonify
from flask import request
from flask import abort

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# Own modules
#from ..model import db_session
from ..model.key import TsigKey

from ..tools import to_bool

from . import api
from . import requires_auth
from . import gen_response

LOG = logging.getLogger(__name__)


#------------------------------------------------------------------------------
@api.route('/api/v1/key')
@requires_auth
def api_all_keys():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    keys = TsigKey.all_keys()

    info = {
        'status': 'OK',
        'keys': [],
        'count': len(keys)
    }
    for key in keys:
        info['keys'].append(key.to_namespace().__dict__)

    return gen_response(info)

#------------------------------------------------------------------------------
@api.route('/api/v1/key/id/<int:key_id>')
@requires_auth
def api_show_key(key_id):
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    key = TsigKey.get_key_by_id(key_id)
    if not key:
        info = {
            'status': 'Not found',
            'response': 'TSIG key {!r} not found.'.format(key_id)
        }
        return gen_response(info)

    info = {
        'status': 'OK',
        'key': key.to_namespace().__dict__,
    }

    return gen_response(info)

#------------------------------------------------------------------------------
@api.route('/api/v1/key/add', methods=['POST'])
@requires_auth
def api_add_key():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    params = {}
    if 'name' not in request.form or 'value' not in request.form:
        errors = []
        if 'name' not in request.form:
            errors.append("No name for the key provided.")
        if 'value' not in request.form:
            errors.append("No value for the key provided.")
        info = {
            'status': 400,
            'response': "Could not add key, necessary fields not given.",
            'errors': errors,
        }
        return gen_response(info)

    params['name'] = request.form['name']
    params['value'] = request.form['value']
    if 'disabled' in request.form:
        params['disabled'] = to_bool(request.form['disabled'])
    if 'enabled' in request.form and 'disabled' not in params:
        if to_bool(request.form['enabled']):
            params['disabled'] = False
        else:
            params['disabled'] = True
    if 'description' in request.form:
        params['description'] = request.form['description']

    info = TsigKey.add_key(**params)
    return gen_response(info)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
