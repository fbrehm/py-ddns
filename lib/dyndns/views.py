#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2010 - 2017 by Frank Brehm, Berlin
@summary: All modules for Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging

# Third party modules

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
from .constants import STATIC_DIR, TEMPLATES_DIR

from .model import engine, db_session

LOG = logging.getLogger(__name__)

api = Blueprint(
    'api', __name__,
    static_folder=STATIC_DIR,
    template_folder=TEMPLATES_DIR
)


def gen_response(data):
    '''Generate flask response object from JSON depending on status
    '''
    response = jsonify(data)
    if data['status'] is False:
        response.status_code = 500
    elif data['status'] == 'Not Found':
        response.status_code = 404
    else:
        response.status_code = 200
    return response


@api.route('/', defaults={'page': 'index'})
@api.route('/<page>/')
def index(page):
    html_page = '{0}.html'.format(page)
    LOG.debug("Trying to render %r ...", html_page)
    try:
        return render_template(html_page)
    except TemplateNotFound:
        abort(404)



