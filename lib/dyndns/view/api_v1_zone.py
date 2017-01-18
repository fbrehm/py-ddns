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
@api.route('/api/v1/zone')
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
        #LOG.debug("Got zone:\n{}".format(zone.to_namespace().__dict__))
        z = {
            'id': zone.zone_id,
            'zone_name': zone.zone_name,
            'master_ns': zone.master_ns,
            'key_id': zone.key_id,
            'key_name': zone.key_name,
            'key_value': zone.key_value,
            'max_hosts': zone.max_hosts,
            'default_min_wait': None,
            'disabled': zone.disabled,
            'created': zone.created.isoformat(' '),
            'modified': zone.modified.isoformat(' '),
            'description': zone.description,
        }
        if zone.default_min_wait is not None:
            z['default_min_wait'] = zone.default_min_wait.total_seconds()
        #LOG.debug("Got zone:\n{}".format(pp(z)))
        info['zones'].append(z)

    LOG.debug("All zones:\n{}".format(pp(info)))

    return gen_response(info)



#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
