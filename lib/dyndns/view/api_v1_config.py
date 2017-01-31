#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: A module for configuration dependend routes in the Python DynDNS application
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
from flask import url_for

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# Own modules
from ..errors import ConfigNotFoundError

from ..constants import CONFIG

from ..tools import pp

from ..model.config import Config

from . import api
from . import requires_auth
from . import gen_response

LOG = logging.getLogger(__name__)

#------------------------------------------------------------------------------
@api.route('/api/v1/config')
@requires_auth
def get_all_configs():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    info = {
        'status': 'OK',
        'config': {}
    }

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/config/'

    configs = Config.all_valid_configs()
    for cfg in configs:
        cfg_name = cfg.cfg_name
        in_db = False
        c_time = None
        if cfg.created:
            c_time = cfg.created.isoformat(' ')
            in_db = True
        m_time = None
        if cfg.modified:
            m_time = cfg.modified.isoformat(' ')
        conf = {
            'name': cfg_name,
            'value': cfg.value_for_json,
            'value_cfg': cfg.cfg_value,
            'default': cfg.default,
            'valid': cfg.valid,
            'type': cfg.cfg_type,
            'in_db': in_db,
            'created': c_time,
            'modified': m_time,
            'description': cfg.description,
            'url': url_base + str(cfg.cfg_name),
        }
        info['config'][cfg_name] = conf
    info['count'] = len(configs)

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/config/<cfg_name>')
@requires_auth
def get_config(cfg_name):
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    info = {
        'status': 'OK',
        'config': None,
    }

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/config'

    try:
        cfg = Config.get(cfg_name)
    except ConfigNotFoundError as e:
        info = {
            'status': 'Not found',
            'response': 'Configuration {!r} not found.'.format(cfg_name),
            'config': None,
            'url': url_base,
        }
        LOG.error("Trying to get not existing configuration {c!r}: {e}".format(
            c=cfg_name, e=e))
        return gen_response(info)

    in_db = False
    c_time = None
    if cfg.created:
        c_time = cfg.created.isoformat(' ')
        in_db = True
    m_time = None
    if cfg.modified:
        m_time = cfg.modified.isoformat(' ')
    info['config'] = {
        'name': cfg_name,
        'value': cfg.value_for_json,
        'value_cfg': cfg.cfg_value,
        'default': cfg.default,
        'valid': cfg.valid,
        'type': cfg.cfg_type,
        'in_db': in_db,
        'created': c_time,
        'modified': m_time,
        'description': cfg.description,
        'url': url_base + '/' + str(cfg.cfg_name),
    }

    return gen_response(info)

#------------------------------------------------------------------------------
@api.route('/api/v1/config/<cfg_name>', methods=['PUT', 'PATCH'])
@requires_auth
def set_config(cfg_name):
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    info = {
        'status': 'OK',
        'config': None,
    }

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/config'

    updates = {}
    if request.method == 'PUT':
        if not 'value' in request.values:
            errors = ['No new value of the configuration given.']
            info = {
                'status': 400,
                'response': "Could not update configuration.",
                'errors': errors,
            }
            LOG.warn("Could not update configuration {c!r}:\n{e}".format(
                c=cfg_name, e=pp(errors)))
            return gen_response(info)
        updates['value'] = request.values['value']
        updates['description'] = None
    else:
        if 'value' in request.values:
            updates['value'] = request.values['value']
    if 'description' in request.values:
        updates['description'] = request.values['description']

    try:
        cfg = Config.update(cfg_name, updates)
    except ConfigNotFoundError as e:
        info = {
            'status': 'Not found',
            'response': 'Configuration {!r} not found.'.format(cfg_name),
            'config': None,
            'url': url_base,
        }
        LOG.error("Trying to update not existing configuration {c!r}: {e}".format(
            c=cfg_name, e=e))
        return gen_response(info)

    in_db = False
    c_time = None
    if cfg.created:
        c_time = cfg.created.isoformat(' ')
        in_db = True
    m_time = None
    if cfg.modified:
        m_time = cfg.modified.isoformat(' ')
    info['config'] = {
        'name': cfg_name,
        'value_cfg': cfg.cfg_value,
        'value': cfg.value_for_json,
        'default': cfg.default,
        'valid': cfg.valid,
        'type': cfg.cfg_type,
        'in_db': in_db,
        'created': c_time,
        'modified': m_time,
        'description': cfg.description,
        'url': url_base + '/' + str(cfg_name),
    }
    info['response'] = 'Successful updated configuration {!r}.'.format(cfg_name)

    return gen_response(info)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
