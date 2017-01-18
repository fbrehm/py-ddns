#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: A module for user dependend routes in the Python DynDNS application
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
from ..model.user import User

from . import api
from . import requires_auth
from . import gen_response

LOG = logging.getLogger(__name__)

digits_re = re.compile(r'\d')
capitals_re = re.compile(r'[A-Z]')
small_re = re.compile(r'[a-z]')
specials_re = re.compile(r'[\.\:,;\-_~+*$%&\{\[\]\}^\r([\)\?/\'\"]')
valid_re = re.compile(
    r'^[\da-z\.\:,;\-_~+*$%&\{\[\]\}^\r([\)\?/\'\"]+$',
    re.IGNORECASE)


#------------------------------------------------------------------------------
@api.route('/api/v1/user')
@requires_auth
def api_cur_user():
    ctx = stack.top
    info = {
        'status': 'OK',
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


#------------------------------------------------------------------------------
@api.route('/api/v1/users')
@requires_auth
def api_all_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    users = User.all_users()

    info = {
        'status': 'OK',
        'users': [],
        'count': len(users)
    }

    for user in users:
        u = user.to_namespace().__dict__
        u['passwd'] = user.passwd[0:3] + ' ********'
        info['users'].append(u)

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/user/password/<new_password>')
@requires_auth
def api_cur_user_set_pwd(new_password):
    ctx = stack.top
    if not new_password:
        info = {
            'status': 420,
            'response': "No password given.",
        }
        return gen_response(info)

    enc_pwd = crypt.crypt(new_password, ctx.cur_user.passwd)
    if enc_pwd == ctx.cur_user.passwd:
        info = {
            'status': 406,
            'response': "New password is matching the old one, no changes.",
        }
        return gen_response(info)

    errors = []
    if len(new_password) < 8:
        errors.append("New password is too short (min. 8 characters).")
    if not valid_re.search(new_password):
        errors.append("New password contains invalid characters.")
    if not small_re.search(new_password):
        errors.append("New password contains no small letters.")
    if not capitals_re.search(new_password):
        errors.append("New password contains no capitals.")
    if not digits_re.search(new_password):
        errors.append("New password contains no digits.")
    if not specials_re.search(new_password):
        errors.append("New password contains no special characters.")

    if errors:
        info = {
            'status': 420,
            'response': "Invalid password.",
            'errors': errors,
        }
        return gen_response(info)

    salt = crypt.mksalt(crypt.METHOD_SHA512)
    enc_pwd = crypt.crypt(new_password, salt)
    updates = {
        'passwd': enc_pwd,
        'modified': text('CURRENT_TIMESTAMP')
    }
    LOG.debug("Setting password for user {u!r} to {p!r} ...".format(
        u=ctx.cur_user.user_name, p=enc_pwd))

    db_session = User.__session__
    try:
        db_session.query(User).filter(
            User.user_name == ctx.cur_user.user_name).update(updates, synchronize_session=False)
        db_session.commit()
    except SQLAlchemyError as e:
        db_session.rollback()
        info = {
            'status': 500,
            'response': 'Could not change password of user {!r}.'.format(ctx.cur_user.user_name),
            'errors': [str(e)],
        }
        LOG.error("{c} on changing password of user {u!r}: {e}".format(
            c=e.__class__.__name__, u=ctx.cur_user.user_name, e=e))
        return gen_response(info)

    info = {
        'status': 'OK',
        'response': "Successful set new password for user {!r}.".format(ctx.cur_user.user_name),
    }
    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/user/id/<user_id>')
@api.route('/api/v1/user/name/<user_id>')
@requires_auth
def api_user_from_id(user_id):
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    user = User.get_user(user_id)
    if not user:
        info = {
            'status': 'Not found',
            'response': 'User {!r} not found.'.format(user_id)
        }
        return gen_response(info)
    info = {
        'status': 'OK',
        'user': {
            'id': user.user_id,
            'user_name': user.user_name,
            'full_name': user.full_name,
            'email': user.email,
            'passwd': user.passwd[0:3] + ' ********',
            'is_admin': user.is_admin,
            'is_sticky': user.is_sticky,
            'max_hosts': user.max_hosts,
            'disabled': user.disabled,
            'created': user.created.isoformat(' '),
            'modified': user.modified.isoformat(' '),
            'description': user.description,
        }
    }
    return gen_response(info)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
