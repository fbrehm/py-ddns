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
from flask import url_for

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

#------------------------------------------------------------------------------
@api.route('/api/v1/zone', methods=['POST'])
@requires_auth
def api_add_zone():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    url_base = url_for('.index', _external=True)
    url = url_base + 'api/v1/zone'

    (ok, zone_data, errors) = check_zonedata(complete=True)

    if not ok or errors:
        info = {
            'status': 400,
            'response': "Error on new user.",
            'errors': errors,
            'url': url
        }
        return gen_response(info)

    info = {
        'status': 'ok',
        'url': url,
        'errors': errors,
        'zone': zone_data,
        'response': "Easy peasy",
    }
    return gen_response(info)


#------------------------------------------------------------------------------
def check_zonedata(complete=False):
    """
    Checking the validity of given data about a zone.

    @param complete: Checking for complete user data (for PUT and POST requests)
    @type complete: bool

    @return: a tuple of three values:
                * a boolean flag, whether the new data are okay
                * a dict with the zone data, which can be used directly
                    for adding or updating
                * a list with all error messages

    """

    ok = True
    zone_data = {}
    errors = []

    valid_fields = (
        'zone_name', 'master_ns', 'key_id', 'key_name', 'max_hosts',
        'default_min_wait', 'disabled', 'description')

    # Check for new zone name
    if 'zone_name' in request.values:
        new_name = request.values['zone_name'].strip()
        if new_name:
            zone_data['zone_name'] = new_name
        elif complete:
            errors.append("New zone name is empty.")
    elif complete:
        errors.append("No new name given for zone.")

    if 'master_ns' in request.values:
        ns = request.values['master_ns'].strip()
        if ns:
            zone_data['master_ns'] = ns
        else:
            zone_data['master_ns'] = None
    elif complete:
        errors.append("No master name server given for zone.")

    (key_id, key_errors) = check_zone_key(complete=complete)
    if key_id is not None:
        zone_data['key_id'] = key_id
    elif key_errors:
        errors += key_errors

    (mh, mh_errors) = check_zone_max_hosts(complete=complete)
    if mh is not None:
        zone_data['max_hosts'] = mh
    elif mh_errors:
        errors += mh_errors
    else:
        zone_data['max_hosts'] = None

    (mw, mw_errors) = check_zone_min_wait(complete=complete)
    if mw is not None:
        zone_data['default_min_wait'] = mw
    elif mw_errors:
        errors += mw_errors
    else:
        zone_data['default_min_wait'] = None

    # Checking the disabled flag
    if 'disabled' in request.values:
        zone_data['disabled'] = to_bool(request.values['disabled'])
    elif complete:
        zone_data['disabled'] = False

    # Checking the description of the zone
    if 'description' in request.values:
        zone_data['description'] = request.values['description'].strip()
    elif complete:
        zone_data['description'] = None

    for key in request.values.keys():
        if key in valid_fields:
            continue
        vals = request.values.getlist(key)
        errors.append("Unknown field {f!r} with value {v} given.".format(
            f=key, v=pp(vals)))

    if errors:
        ok = False

    LOG.debug("Checked zone data ok: {o!r}\nzone_data:\n{z}\nerrors:\n{e}".format(
        o=ok, z=pp(zone_data), e=pp(errors)))

    return (ok, zone_data, errors)


#------------------------------------------------------------------------------
def check_zone_key(complete=False):

    errors = []
    key_id = None

    if 'key_id' in request.values:
        kid_str = request.values['key_id'].strip()
        if kid_str:
            try:
                key_id = int(kid_str)
            except Exception as e:
                msg = "Invalid key Id {i!r} given: {e}".format(
                    i=request.values['key_id'], e=e)
                errors.append(msg)
                return (None, errors)
            try:
                key = TsigKey.get_key_by_id(key_id)
            except Exception as e:
                msg = "TSIG key with Id {i!r} not found: {e}".format(
                    i=key_id, e=e)
                errors.append(msg)
                return (None, errors)
            if not key:
                msg = "TSIG key with Id {i!r} not found.".format(i=key_id)
                errors.append(msg)
                return (None, errors)
            return (key_id, [])
        else:
            errors.append("Given key Id was empty.")
            return (None, errors)

    if 'key_name' in request.values:
        key_name = request.values['key_name'].strip()
        if key_name:
            try:
                key = TsigKey.get_keys_by_name(key_name)
            except Exception as e:
                msg = "TSIG key with name {n!r} not found: {e}".format(
                    n=request.values['key_name'], e=e)
                errors.append(msg)
                return (None, errors)
            if not key:
                msg = "TSIG key with name {n!r} not found.".format(
                    n=request.values['key_name'])
                errors.append(msg)
                return (None, errors)
            return (key.key_id, [])
        else:
            errors.append("Given key name was empty.")
            return (None, errors)

    if complete:
        errors.append("Neither a key Id nor a key name were given.")
    return (None, errors)

#------------------------------------------------------------------------------
def check_zone_max_hosts(complete=False):

    errors = []
    mh = None

    if 'max_hosts' in request.values:
        mh_str = request.values['max_hosts'].strip()
        if mh_str:
            try:
                mh = int(mh_str)
            except Exception as e:
                msg = "Invalid max_hosts {m!r} given: {e}".format(
                    m=request.values['max_hosts'], e=e)
                errors.append(msg)
                return (None, errors)
            if mh < 0:
                msg = "Invalid max_hosts {} given, it must be greater than zero.".format(mh)
                return (None, [msg])
            if mh == 0:
                mh = None
            return (mh, [])
        else:
            return (None, [])

    if complete:
        errors.append("No max_hosts given.")
    return (None, errors)

#------------------------------------------------------------------------------
def check_zone_min_wait(complete=False):

    errors = []
    mw = None

    if 'default_min_wait' in request.values:
        mw_str = request.values['default_min_wait'].strip()
        if mw_str:
            try:
                mw = int(mw_str)
            except Exception as e:
                msg = "Invalid default_min_wait {m!r} given: {e}".format(
                    m=request.values['default_min_wait'], e=e)
                errors.append(msg)
                return (None, errors)
            if mw < 0:
                msg = "Invalid default_min_wait {} given, it must be greater than zero.".format(mw)
                return (None, [msg])
            if mw == 0:
                mw = None
            return (mw, [])
        else:
            return (None, [])

    if complete:
        errors.append("No default_min_wait given.")
    return (None, errors)

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
