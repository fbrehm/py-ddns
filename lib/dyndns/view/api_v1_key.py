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


