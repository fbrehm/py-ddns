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


# Own modules
from .constants import STATIC_DIR, TEMPLATES_DIR, LOGIN_REALM

from .model import db_session

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
        if data['status'] is False:
            response.status_code = 500
        elif data['status'] == 'Not Found':
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
    if username == 'admin' and password == 'secret':
        return True
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
