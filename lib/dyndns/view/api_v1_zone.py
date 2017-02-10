#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: A module for zones dependend routes in the Python DynDNS application
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
from ..model.zone import Zone, ZoneView

from ..tools import to_bool, pp

from . import api
from . import requires_auth
from . import gen_response

LOG = logging.getLogger(__name__)


#------------------------------------------------------------------------------
@api.route('/api/v1/all_zones')
@requires_auth
def api_all_zones():
    ctx = stack.top
    is_admin = ctx.cur_user.is_admin

    zones = []
    if is_admin:
        zones = ZoneView.all_zones()
    else:
        zones = ZoneView.all_zones(enabled=True)

    info = {
        'status': 'OK',
        'zones': [],
        'count': len(zones)
    }
    for zone in zones:
        info['zones'].append(zone.zone_name)

    return gen_response(info)

#------------------------------------------------------------------------------
@api.route('/api/v1/zone')
@api.route('/api/v1/zones')
@requires_auth
def api_all_zones_ext():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    zones = ZoneView.all_zones()

    info = {
        'status': 'OK',
        'zones': [],
        'count': len(zones)
    }
    for zone in zones:
        z = zone.to_namespace(for_json=True).__dict__
        info['zones'].append(z)

    LOG.debug("All zones:\n{}".format(pp(info)))

    return gen_response(info)



#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
