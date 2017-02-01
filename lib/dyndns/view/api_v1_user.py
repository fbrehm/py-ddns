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
from ..constants import CONFIG

from ..tools import pp, to_bool

from ..model.user import User
from ..model.config import Config

from ..errors import UsernameExistsError

from . import api
from . import requires_auth
from . import requires_auth_set_passwd
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
email_re = re.compile(
    r'^[a-z0-9._%-+]+@[a-z0-9._%-]+.[a-z]{2,6}$',
    re.IGNORECASE)


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
@api.route('/api/v1/cur_user', methods=['PATCH'])
@requires_auth_set_passwd
def api_cur_user_patch():
    ctx = stack.top

    user_data = {}
    if 'password' in request.form:
        user_data['password'] = request.form['password']
    if 'full_name' in request.form:
        user_data['full_name'] = request.form['full_name']
    if 'email' in request.form:
        user_data['email'] = request.form['email']

    return update_user(ctx.cur_user.user_id, user_data, ctx)


#------------------------------------------------------------------------------
@api.route('/api/v1/cur_user/password', methods=['PATCH'])
@requires_auth
def api_cur_user_set_pwd():
    ctx = stack.top

    if 'new_password' not in request.form:
        info = {
            'status': 400,
            'response': "No password given (form field 'new_password').",
        }
        return gen_response(info)

    user_data = {'password': request.form['new_password']}
    return update_user(ctx.cur_user.user_id, user_data, ctx)


#------------------------------------------------------------------------------
def update_user(user_id, user_data, ctx):

    errors = []
    updates = {}

    passwd_restrictions = Config.get_password_restrictions()

    LOG.debug("Got data of user {i!r} given:\n{d}".format(
        i=str(user_id), d=pp(user_data)))

    if 'user_name' in user_data:
        if empty_re.search(user_data['user_name']):
            errors.append("New username is empty.")
        else:
            updates['user_name'] = user_data['user_name']

    if 'password' in user_data:

        new_pwd = user_data['password']
        passwd_wrong = False
        while True:

            if empty_re.search(new_pwd):
                errors.append("New password is empty.")
                break

            enc_pwd = crypt.crypt(new_pwd, ctx.cur_user.passwd)
            if enc_pwd == ctx.cur_user.passwd:
                LOG.debug("New password is matching the old password.")
                break

            if len(new_pwd) < passwd_restrictions['min_len']:
                errors.append("New password is too short (min. {} characters).".format(
                    passwd_restrictions['min_len']))
                passwd_wrong = True
            if not valid_re.search(new_pwd):
                errors.append("New password contains invalid characters.")
                passwd_wrong = True
            if passwd_restrictions['small_chars_required'] and not small_re.search(new_pwd):
                errors.append("New password contains no small letters.")
                passwd_wrong = True
            if passwd_restrictions['capitals_required'] and not capitals_re.search(new_pwd):
                errors.append("New password contains no capitals.")
                passwd_wrong = True
            if passwd_restrictions['digits_required'] and not digits_re.search(new_pwd):
                errors.append("New password contains no digits.")
                passwd_wrong = True
            if passwd_restrictions['special_chars_required'] and not specials_re.search(new_pwd):
                errors.append("New password contains no special characters.")
                passwd_wrong = True

            if passwd_wrong:
                break

            salt = crypt.mksalt(crypt.METHOD_SHA512)
            enc_pwd = crypt.crypt(new_pwd, salt)
            updates['passwd'] = enc_pwd
            LOG.debug("Setting password for user {u!r} to {p!r} ...".format(
                u=ctx.cur_user.user_name, p=enc_pwd))
            break

    if 'full_name' in user_data:
        if empty_re.search(user_data['full_name']):
            errors.append("New full name is empty.")
        else:
            updates['full_name'] = user_data['full_name']

    if 'email' in user_data:
        if empty_re.search(user_data['email']):
            errors.append("New email address is empty.")
        elif not email_re.search(user_data['email']):
            errors.append("Wrong E-Mail address {!r}.".format(user_data['email']))
        else:
            updates['email'] = user_data['email']

    if 'max_hosts' in user_data:
        updates['max_hosts'] = user_data['max_hosts']

    if 'is_admin' in user_data:
        updates['is_admin'] = user_data['is_admin']

    if 'disabled' in user_data:
        updates['disabled'] = user_data['disabled']

    if 'description' in user_data:
        updates['description'] = user_data['description']

    if errors:
        info = {
            'status': 400,
            'response': "Could not update user data.",
            'errors': errors,
        }
        LOG.warn("Could not update data for user {i!r}:\n{e}".format(
            i=str(user_id), e=pp(errors)))
        return gen_response(info)

    if not updates.keys():
        info = {
            'status': 406,
            'response': "No changes for user data found.",
        }
        LOG.warn("No changes for user {!r} found.".format(str(user_id)))
        return gen_response(info)

    info = User.update_user(user_id, updates)
    if info['status'] != 'OK' and info['status'] != 400:
        info['response'] = 'Could not change data of user {!r}.'.format(user_id)
    elif info['status'] == 'OK':
        info['response'] = "Successful changed data for user {!r}.".format(user_id)
    url = url_for('.index', _external=True) + 'api/v1/user/' + str(user_id)
    if 'user' in info:
        info['user']['url']= url
        if 'created' in info['user'] and info['user']['created']:
            info['user']['created'] = info['user']['created'].isoformat(' ')
        if 'modified' in info['user'] and info['user']['modified']:
            info['user']['modified'] = info['user']['modified'].isoformat(' ')
    else:
        info['url'] = url

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

    total_count = User.total_count()
    users = User.all_users()
    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

    info = {
        'status': 'OK',
        'users': [],
        'total_count': total_count,
    }

    for user in users:
        u = user.to_namespace().__dict__
        u['passwd'] = user.passwd[0:3] + ' ********'
        u['url'] = url_base + str(user.user_id)
        info['users'].append(u)

    return gen_response(info)

#------------------------------------------------------------------------------
@api.route('/api/v1/users/count')
@requires_auth
def api_count_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    total_count = User.total_count()

    info = {
        'status': 'OK',
        'total_count': total_count,
    }

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/users/admins')
@requires_auth
def api_all_admin_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    total_count = User.total_count(is_admin=True)
    users = User.all_users(is_admin=True)
    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

    info = {
        'status': 'OK',
        'users': [],
        'total_count': total_count,
    }

    for user in users:
        u = user.to_namespace().__dict__
        u['passwd'] = user.passwd[0:3] + ' ********'
        u['url'] = url_base + str(user.user_id)
        info['users'].append(u)

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/users/enabled')
@requires_auth
def api_all_enabled_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    total_count = User.total_count(enabled=True)
    users = User.all_users(enabled=True)
    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

    info = {
        'status': 'OK',
        'users': [],
        'total_count': total_count,
    }

    for user in users:
        u = user.to_namespace().__dict__
        u['passwd'] = user.passwd[0:3] + ' ********'
        u['url'] = url_base + str(user.user_id)
        info['users'].append(u)

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/users/enabled/count')
@requires_auth
def api_count_enabled_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    total_count = User.total_count(enabled=True)

    info = {
        'status': 'OK',
        'total_count': total_count,
    }

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/users/disabled')
@requires_auth
def api_all_disabled_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    total_count = User.total_count(enabled=False)
    users = User.all_users(enabled=False)
    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

    info = {
        'status': 'OK',
        'users': [],
        'total_count': total_count,
    }

    for user in users:
        u = user.to_namespace().__dict__
        u['passwd'] = user.passwd[0:3] + ' ********'
        u['url'] = url_base + str(user.user_id)
        info['users'].append(u)

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/users/disabled/count')
@requires_auth
def api_count_disabled_users():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    total_count = User.total_count(enabled=False)

    info = {
        'status': 'OK',
        'total_count': total_count,
    }

    return gen_response(info)


#------------------------------------------------------------------------------
@api.route('/api/v1/user/<user_id>')
@api.route('/api/v1/users/id/<user_id>')
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
@api.route('/api/v1/user/<user_id>', methods=['PATCH', 'PUT'])
@requires_auth
def api_update_user(user_id):
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

    default_max_hosts = Config.get('default_user_max_hosts').value

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

    user_data = {}
    errors = []
    if request.method == 'PUT':
        if not 'user_name' in request.values:
            errors.append("No new username given for user.")
        if not 'password' in request.values:
            errors.append("No new password given for user.")
        if not 'full_name' in request.values:
            errors.append("No new full user name given for user.")
        if not 'email' in request.values:
            errors.append("No new email address given for user.")
        user_data['max_hosts'] = default_max_hosts
        user_data['is_admin'] = False
        user_data['disabled'] = False
        user_data['description'] = None


    if 'user_name' in request.values:
        user_data['user_name'] = request.values['user_name']
    if 'password' in request.values:
        user_data['password'] = request.values['password']
    if 'full_name' in request.values:
        user_data['full_name'] = request.values['full_name']
    if 'email' in request.values:
        user_data['email'] = request.values['email']
    if 'max_hosts' in request.values:
        mh = request.values['max_hosts']
        if empty_re.search(mh):
            user_data['max_hosts'] = None
        else:
            try:
                mh = int(mh)
            except ValueError as e:
                errors.append("Invalid value {v!r} for max_hosts: {e}".format(
                    v=request.values['max_hosts'], e=e))
            else:
                if mh < 0:
                    errors.append("Invalid value {v!r} for max_hosts: {e}".format(
                        v=request.values['max_hosts'],
                        e="No negative values allowed."))
                else:
                    user_data['max_hosts'] = mh
    if 'is_admin' in request.values:
        user_data['is_admin'] = to_bool(request.values['is_admin'])
    if 'disabled' in request.values:
        user_data['disabled'] = to_bool(request.values['disabled'])
    if 'description' in request.values:
        user_data['description'] = request.values['description'].strip()

    if errors:
        info = {
            'status': 400,
            'response': "Error updating user {}.".format(user_id),
            'errors': errors,
            'url': url_base + str(user_id),
        }
        return gen_response(info)

    return update_user(user_id, user_data, ctx)


#------------------------------------------------------------------------------
@api.route('/api/v1/users/name/<user_id>')
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
