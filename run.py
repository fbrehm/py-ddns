#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import sys
import os
import atexit
import logging

# Third party modules
from six import PY2

# Own modules
libdir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'lib'))
sys.path.insert(0, libdir)

from dyndns import configure_logging
from dyndns import create_app

LOG = logging.getLogger("dyndns")

if PY2:
    reload(sys)
    sys.setdefaultencoding("utf-8")


#------------------------------------------------------------------------------
def main():
    atexit.register(shutdown)
    configure_logging()

    LOG.info("Starting dyndns ...")
    app = create_app()
    app.run(
        threaded=True,
        host=app.config.get('HOST', '::'),
        port=app.config.get('SERVER_PORT', 5000),
        debug=app.config.get('DEBUG', True)
    )

#------------------------------------------------------------------------------
def shutdown():
    LOG.info("Shutting down dyndns")


#==============================================================================

if __name__ == '__main__':
    main()

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
