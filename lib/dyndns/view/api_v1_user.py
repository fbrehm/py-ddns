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
from flask import url_for

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
empty_re = re.compile(r'^\s*$')


#------------------------------------------------------------------------------
@api.route('/api/v1/cur_user')
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
        url = url_for('.index', _external=True)
        if not url.endswith('/'):
            url += '/'
        url += 'api/v1/user/{}'.format(ctx.cur_user.user_id)
        info['url'] = url
    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/cur_user/password')
@requires_auth
def api_cur_user_get_passwd():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    info = {
        'status': 'OK',
        'pasword': ctx.cur_user.passwd
    }
    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/cur_user/password', methods=['PATCH'])
@requires_auth
def api_cur_user_set_pwd():
    ctx = stack.top

    new_pwd = None
    if 'new_password' in request.form:
        new_pwd = request.form['new_password']
    else:
        info = {
            'status': 400,
            'response': "No password given (form field 'new_password').",
        }
        return gen_response(info)

    enc_pwd = crypt.crypt(new_pwd, ctx.cur_user.passwd)
    if enc_pwd == ctx.cur_user.passwd:
        info = {
            'status': 406,
            'response': "New password is matching the old one, no changes.",
        }
        return gen_response(info)

    if empty_re.search(new_pwd):
        info = {
            'status': 400,
            'response': "New password is empty.",
        }
        return gen_response(info)

    min_len_passwd = 4
    passwd_restrictions = {
        'min_len': 4,
        'small_chars_required': True,
        'capitals_required': True,
        'digits_required': False,
        'special_chars_required': False,
    }

    errors = []
    if len(new_pwd) < passwd_restrictions['min_len']:
        errors.append("New password is too short (min. {} characters).".format(
            passwd_restrictions['min_len']))
    if not valid_re.search(new_pwd):
        errors.append("New password contains invalid characters.")
    if passwd_restrictions['small_chars_required'] and not small_re.search(new_pwd):
        errors.append("New password contains no small letters.")
    if passwd_restrictions['capitals_required'] and not capitals_re.search(new_pwd):
        errors.append("New password contains no capitals.")
    if passwd_restrictions['digits_required'] and not digits_re.search(new_pwd):
        errors.append("New password contains no digits.")
    if passwd_restrictions['special_chars_required'] and not specials_re.search(new_pwd):
        errors.append("New password contains no special characters.")

    if errors:
        info = {
            'status': 420,
            'response': "Invalid password.",
            'errors': errors,
        }
        return gen_response(info)

    salt = crypt.mksalt(crypt.METHOD_SHA512)
    enc_pwd = crypt.crypt(new_pwd, salt)
    updates = {'passwd': enc_pwd}
    LOG.debug("Setting password for user {u!r} to {p!r} ...".format(
        u=ctx.cur_user.user_name, p=enc_pwd))

    info = User.update_user(ctx.cur_user.user_id, updates)
    if info['status'] != 'OK':
        info['response'] = 'Could not change password of user {!r}.'.format(
            ctx.cur_user.user_name)
    else:
        info['response'] = "Successful set new password for user {!r}.".format(
            ctx.cur_user.user_name)

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/user')
@api.route('/api/v1/users')
@requires_auth
def api_all_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    users = User.all_users()
    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

    info = {
        'status': 'OK',
        'users': [],
        'count': len(users)
    }

    for user in users:
        u = user.to_namespace().__dict__
        u['passwd'] = user.passwd[0:3] + ' ********'
        u['url'] = url_base + str(user.user_id)
        info['users'].append(u)

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/user/<user_id>')
@api.route('/api/v1/user/id/<user_id>')
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

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

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
            'url': url_base + str(user.user_id),
        }
    }
    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/user/name/<user_id>')
@requires_auth
def api_user_from_name(user_id):
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

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

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
            'url': url_base + str(user.user_id),
        }
    }
    return gen_response(info)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
