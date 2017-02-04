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

    url_base = url_for('.index', _external=True)
    url = url_base + 'api/v1/cur_user'
    user_id = ctx.cur_user.user_id

    (ok, user_data, errors) = check_userdata(complete=False, restricted=True)

    if not ok or errors:
        info = {
            'status': 400,
            'response': "Error updating current user.",
            'errors': errors,
            'url': url,
        }
        return gen_response(info)

    if not user_data.keys():
        info = {
            'status': 406,
            'response': "No changes for current user found.",
            'url': url,
        }
        LOG.warn("No changes for user {!r} found.".format(str(user_id)))
        return gen_response(info)

    # The underlying update
    info = User.update_user(user_id, user_data)

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
@api.route('/api/v1/cur_user/password', methods=['PATCH'])
@api.route('/api/v1/cur_user/password/<password>', methods=['PATCH'])
@requires_auth
def api_cur_user_set_pwd(password):
    ctx = stack.top

    url_base = url_for('.index', _external=True)
    url = url_base + 'api/v1/cur_user/password'

    user_id = ctx.cur_user.user_id

    new_pwd = password
    if 'password' in request.values:
        new_pwd = request.values['password']
    elif 'new_password' in request.values:
        new_pwd = request.values['new_password']

    if not new_pwd:
        info = {
            'status': 400,
            'response': "No password given.",
            'url': url,
        }
        return gen_response(info)

    user_data = {}
    errors = []

    (pwd_status, pwd_errors) = check_password(new_pwd)
    if not pwd_status:
        errors += pwd_errors
    else:
        if pwd_errors:
            LOG.warn("Got some password check warnings:\n{}".format(pp(pwd_errors)))
        salt = crypt.mksalt(crypt.METHOD_SHA512)
        enc_pwd = crypt.crypt(new_pwd, salt)
        user_data['passwd'] = enc_pwd

    if errors:
        info = {
            'status': 400,
            'response': "Error updating password of current user.",
            'errors': errors,
            'url': url,
        }
        return gen_response(info)

    # The underlying update
    info = User.update_user(user_id, user_data)

    if 'user' in info:
        info['user']['url']= url
        if 'created' in info['user'] and info['user']['created']:
            info['user']['created'] = info['user']['created'].isoformat(' ')
        if 'modified' in info['user'] and info['user']['modified']:
            info['user']['modified'] = info['user']['modified'].isoformat(' ')
    else:
        info['url'] = url

    if info['status'] == 'OK':
        info['response'] = 'Successful changed password of current user.'

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
def check_password(new_pwd, old_pwd=None):
    """
    Checking the given password for restrictions.

    @param new_pwd: the new (unencrypted) passsword to check.
    @type new_pwd: str
    @param old_pwd: the old (encrypted) password, or None, if it is a ne user
    @type old_pwd: str or None

    @return: a tuple of two values:
                * an integer:
                    * 1, if password is ok
                    * 0, if password has errors and is invalid
                    * 2, if password is ok, but equal to the old one
                * a list of error messages. if the password is valid, then
                  these are only some informal messages

    """

    errors = []
    status = 1

    passwd_restrictions = Config.get_password_restrictions()
    LOG.debug("Checking or password restrictions:\n{}".format(pp(passwd_restrictions)))

    if empty_re.search(new_pwd):
        errors.append("New password is empty.")
        return (0, errors)

    if old_pwd:
        enc_pwd = crypt.crypt(new_pwd, old_pwd)
        if enc_pwd == old_pwd:
            errors.append("New password is matching the old password.")
            return (2, errors)

    if len(new_pwd) < passwd_restrictions['min_len']:
        errors.append("New password is too short (min. {} characters).".format(
            passwd_restrictions['min_len']))
        status = 0

    if not valid_re.search(new_pwd):
        errors.append("New password contains invalid characters.")
        status = 0

    if passwd_restrictions['small_chars_required'] and not small_re.search(new_pwd):
        errors.append("New password contains no small letters.")
        status = 0

    if passwd_restrictions['capitals_required'] and not capitals_re.search(new_pwd):
        errors.append("New password contains no capitals.")
        status = 0

    if passwd_restrictions['digits_required'] and not digits_re.search(new_pwd):
        errors.append("New password contains no digits.")
        status = 0

    if passwd_restrictions['special_chars_required'] and not specials_re.search(new_pwd):
        errors.append("New password contains no special characters.")
        status = 0

    return (status, errors)


#------------------------------------------------------------------------------
def check_userdata(complete=False, restricted=False):
    """
    Checking the validity of given userdata.

    @param complete: Checking for complete user data (for PUT and POST requests)
    @type complete: bool
    @param restricted: performing a check of restricted data (for the case,
                        a user is updating its own data)
    @type restricted: bool

    @return: a tuple of three values:
                * a boolean flag, whether the new data are okay
                * a dict with the new user data, which can be used directly
                    for adding or updating
                * a list with all error messages

    """

    ok = True

    default_max_hosts = Config.get('default_user_max_hosts').value

    user_data = {}
    errors = []

    valid_fields = (
        'user_name', 'password', 'full_name', 'email', 'max_hosts',
        'is_admin', 'disabled', 'description')

    # Check for new username / loginname
    if 'user_name' in request.values:
        new_name = request.values['user_name'].strip()
        if new_name:
            user_data['user_name'] = new_name
        elif complete:
            errors.append("New username is empty.")
    elif complete:
        errors.append("No new username given for user.")

    # Check for new password
    if 'password' in request.values:
        (pwd_status, pwd_errors) = check_password(request.values['password'])
        if not pwd_status:
            errors += pwd_errors
        else:
            if pwd_errors:
                LOG.warn("Got some password check warnings:\n{}".format(pp(pwd_errors)))
            salt = crypt.mksalt(crypt.METHOD_SHA512)
            enc_pwd = crypt.crypt(new_pwd, salt)
            user_data['passwd'] = enc_pwd
    elif complete:
        errors.append("No new password given for user.")

    # Check for th full user name
    if 'full_name' in request.values:
        if empty_re.search(request.values['full_name']) and complete:
            errors.append("New full name is empty.")
        else:
            user_data['full_name'] = request.values['full_name'].strip()
    elif complete:
        errors.append("No new full user name given for user.")

    # Check for the E-Mail address
    if 'email' in request.values:
        if empty_re.search(request.values['email']) and complete:
            errors.append("New email address is empty.")
        elif not email_re.search(request.values['email']):
            errors.append("Wrong E-Mail address {!r}.".format(
                request.values['email']))
        else:
            user_data['email'] = request.values['email'].strip()
    elif complete:
        errors.append("No new email address given for user.")

    # Checking for the max_hosts value
    if 'max_hosts' in request.values:
        if restricted:
            errors.append("You are not allowed to change the maximum hosts for this user.")
        else:
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
    elif complete:
        user_data['max_hosts'] = default_max_hosts

    # Checking the administrator flag
    if 'is_admin' in request.values:
        if restricted:
            errors.append("You are not allowed to change the administrator flag for this user.")
        else:
            user_data['is_admin'] = to_bool(request.values['is_admin'])
    elif complete:
        user_data['is_admin'] = False

    # Checking the disabled flag
    if 'disabled' in request.values:
        if restricted:
            errors.append("You are not allowed to change the disabled flag for this user.")
        else:
            user_data['disabled'] = to_bool(request.values['disabled'])
    elif complete:
        user_data['disabled'] = False

    # Checking the description of the user
    if 'description' in request.values:
        if restricted:
            errors.append("You are not allowed to change the description for this user.")
        else:
            user_data['description'] = request.values['description'].strip()
    elif complete:
        user_data['description'] = None

    for key in request.values.keys():
        if key in valid_fields:
            continue
        vals = request.values.getlist(key)
        errors.append("Unknown field {f!r} with value {v} given.".format(
            f=key, v=pp(vals)))

    if errors:
        ok = False

    return (ok, user_data, errors)

#------------------------------------------------------------------------------
@api.route('/api/v1/user', methods=['POST'])
@requires_auth
def api_add_user():
    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    url_base = url_for('.index', _external=True)
    url = url_base + 'api/v1/user'

    (ok, user_data, errors) = check_userdata(complete=True)

    if not ok or errors:
        info = {
            'status': 400,
            'response': "Error on new user.",
            'errors': errors,
            'url': url
        }
        return gen_response(info)

    info = User.add_user(user_data)

    if 'user' in info:
        url += '/' + str(info['user'].user_id)
        info['user']['url']= url
        if 'created' in info['user'] and info['user']['created']:
            info['user']['created'] = info['user']['created'].isoformat(' ')
        if 'modified' in info['user'] and info['user']['modified']:
            info['user']['modified'] = info['user']['modified'].isoformat(' ')
    else:
        info['url'] = url

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

    complete = False
    if request.method == 'PUT':
        complete = True

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user/'

    (ok, user_data, errors) = check_userdata(complete=complete)

    if not ok or errors:
        info = {
            'status': 400,
            'response': "Error updating user {}.".format(user_id),
            'errors': errors,
            'url': url_base + str(user_id),
        }
        return gen_response(info)

    if not user_data.keys():
        info = {
            'status': 406,
            'response': "No changes for user data found.",
            'url': url_base + str(user_id),
        }
        LOG.warn("No changes for user {!r} found.".format(str(user_id)))
        return gen_response(info)

    # The underlying update
    info = User.update_user(user_id, user_data)

    url = url_base + str(user_id)
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
