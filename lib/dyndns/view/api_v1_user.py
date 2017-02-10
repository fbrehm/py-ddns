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
from flask import redirect

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

# Own modules
from ..constants import CONFIG

from ..tools import pp, to_bool

from ..model.user import User, get_current_list_limit
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
            'list_limit': ctx.cur_user.list_limit,
        }
    }
    if not ctx.cur_user.list_limit:
        try:
            limit = '[{}]'.format(Config.get('default_list_limit').value)
        except ConfigNotFoundError as e:
            LOG.error("Config parameter {!r} not found.".format('default_list_limit'))
            limit = '<default>'
        info['current_user']['list_limit'] = limit
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
@requires_auth
def api_cur_user_set_pwd():
    ctx = stack.top

    url_base = url_for('.index', _external=True)
    url = url_base + 'api/v1/cur_user/password'

    user_id = ctx.cur_user.user_id

    new_pwd = None
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
@api.route('/api/v1/cur_user/password/<password>', methods=['PATCH'])
@requires_auth
def api_cur_user_set_pwd_path(password):
    ctx = stack.top

    return redirect('api/v1/cur_user/password?password={}'.format(password), code=307)

#------------------------------------------------------------------------------
@api.route('/api/v1/user')
@api.route('/api/v1/users')
@requires_auth
def api_all_users():

    return generate_userlist()


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

    return generate_userlist(is_admin=True)


#------------------------------------------------------------------------------
@api.route('/api/v1/users/enabled')
@requires_auth
def api_all_enabled_users():

    return generate_userlist(enabled=True)


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

    return generate_userlist(enabled=False)


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

    u = user.to_namespace(for_json=True).__dict__
    u['passwd'] = user.passwd[0:3] + ' ********'
    u['url'] = url_base + str(user.user_id)

    info = {
        'status': 'OK',
        'user': u,
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
        'is_admin', 'disabled', 'description', 'list_limit')

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
            enc_pwd = crypt.crypt(request.values['password'], salt)
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

    # Checking for the list_limit value
    if 'list_limit' in request.values:
        ll = request.values['list_limit']
        if empty_re.search(ll):
            user_data['list_limit'] = None
        else:
            try:
                ll = int(ll)
            except ValueError as e:
                errors.append("Invalid value {v!r} for list_limit: {e}".format(
                    v=request.values['list_limit'], e=e))
            else:
                if ll < 0:
                    errors.append("Invalid value {v!r} for list_limit: {e}".format(
                        v=request.values['list_limit'],
                        e="No negative values allowed."))
                else:
                    user_data['list_limit'] = ll
    elif complete:
        user_data['list_limit'] = None

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
        LOG.debug("Got new user:\n{}".format(pp(info['user'])))
        url += '/' + str(info['user']['user_id'])
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
def generate_userlist(is_admin=None, enabled=None):
    """Generates a list of all users (including some filter criteria)
        and returns it as JSON."""

    ctx = stack.top
    if not ctx.cur_user.is_admin:
        # Forbidden, if not an administrator
        abort(403)

    url_base = url_for('.index', _external=True)
    url_base += 'api/v1/user'

    total_count = User.total_count(is_admin=is_admin, enabled=enabled)
    errors = []
    emesg = "Wrong value {v!r} for parameter {p}: {e}"

    limit = get_current_list_limit()
    if 'limit' in request.values:
        if empty_re.match(request.values['limit']):
            limit = None
        else:
            try:
                get_limit = int(request.values.get('limit'))
            except ValueError as e:
                errors.append(emesg.format(
                    v=request.values['limit'], p='limit', e=e))
            else:
                if get_limit >= 1:
                    limit = get_limit
                elif get_limit == 0:
                    limit = None
                else:
                    errors.append(emesg.format(
                        v=get_limit, p='limit',
                        e="The limit may not be negative."))

    offset = None
    if 'offset' in request.values:
        if not empty_re.match(request.values['offset']):
            try:
                offset = int(request.values.get('offset'))
            except ValueError as e:
                errors.append(emesg.format(
                    v=request.values['offset'], p='offset', e=e))
            else:
                if offset < 1:
                    offset = None

    if errors:
        info = {
            'status': 400,
            'response': "Error(s) on getting user list.",
            'errors': errors,
            'url': url_base
        }
        return gen_response(info)

    LOG.debug((
        "Getting user list: limit {l!r}, offset {o!r}, "
        "is_admin={a!r}, enabled={e!r}.").format(
        l=limit, o=offset, a=is_admin, e=enabled))

    users = User.all_users(
        is_admin=is_admin, enabled=enabled, limit=limit, offset=offset)

    info = {
        'status': 'OK',
        'users': [],
        'total_count': total_count,
        'count': len(users),
    }

    for user in users:
        u = user.to_namespace(for_json=True).__dict__
        u['passwd'] = user.passwd[0:3] + ' ********'
        u['url'] = url_base + '/' + str(user.user_id)
        info['users'].append(u)

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
