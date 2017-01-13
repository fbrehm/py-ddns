#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2017 by Frank Brehm, Berlin
@summary: Main view module for Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging
from functools import wraps
import crypt

# Third party modules

import werkzeug
from werkzeug.datastructures import MultiDict

from jinja2 import TemplateNotFound

from flask import Blueprint
from flask import Response
from flask import abort
from flask import current_app
from flask import jsonify
from flask import render_template
from flask import request

try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

# Own modules
from .constants import STATIC_DIR, TEMPLATES_DIR, LOGIN_REALM

from .model import db_session
from .model.user import User

from .tools import pp, to_bool

LOG = logging.getLogger(__name__)

api = Blueprint(
    'api', __name__,
    static_folder=STATIC_DIR,
    template_folder=TEMPLATES_DIR
)


#------------------------------------------------------------------------------
def gen_response(data):
    '''Generate flask response object from JSON depending on status
    '''
    response = jsonify(data)
    if 'status' in data:
        state = data['status']
        state_int = 0
        try:
            state_int = int(state)
        except ValueError:
            pass
        if state_int and state_int >= 100 and state_int < 600:
            response.status_code = state_int
        elif state is False:
            response.status_code = 500
        elif state.lower() == 'not found':
            response.status_code = 404
        else:
            response.status_code = 200
    else:
        # I'm a teapot
        response.status_code = 418
    return response


#------------------------------------------------------------------------------
def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """

    if not password:
        LOG.debug("No password given for user {!r}.".format(username))
        return False

    ctx = stack.top

    user = User.query.filter(User.user_name == username).first()

    if user:
        LOG.debug("Found user:\n{}".format(pp(user)))
        cur_pwd = user.passwd
        enc_pwd = crypt.crypt(password, cur_pwd)
        if enc_pwd == cur_pwd:
            ctx.cur_user = user.to_namespace()
            LOG.debug("Authorization for user {!r} confirmed.".format(username))
            LOG.debug("Current user:\n{}".format(pp(ctx.cur_user.__dict__)))
            return True
        else:
            LOG.debug("Password {!r} does not match current password.".format(
                password))
            return False
    else:
        LOG.debug("No user found for username {!r}.".format(username))
        return False

    LOG.debug("Got invalid username {u!r} and password {p!r}.".format(
        u=username, p=password))
    return False


#------------------------------------------------------------------------------
def authenticate():
    """Sends a 401 response that enables basic auth"""
    realm = 'Basic realm="{}"'.format(LOGIN_REALM)
    resp_txt = (
        'Could not verify your access level for URL {!r}.\n'
        'You have to login with proper credentials.\n').format(request.url)
    LOG.debug("Unauthenticated access to path {!r}.".format(request.path))
    return Response(
        resp_txt, status=401, mimetype='text/plain',
        headers={'WWW-Authenticate': realm})


#------------------------------------------------------------------------------
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


#------------------------------------------------------------------------------
# Index page - normal HTML page
@api.route('/', defaults={'page': 'index'})
@api.route('/<page>/')
def index(page):
    html_page = '{0}.html'.format(page)
    LOG.debug("Trying to render %r ...", html_page)
    try:
        return render_template(html_page)
    except TemplateNotFound:
        abort(404)


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
