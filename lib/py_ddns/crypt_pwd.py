#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@license: LGPL3+
@copyright: © 2010 - 2014 Berlin
@summary: Module for encrypting and checking a password
"""

# Common modules
import os
import sys

# Third party modules
from passlib.hash import sha256_crypt

def encrypt(passwd):
    sha256_crypt.encrypt(passwd)


#========================================================================

# vim: fileencoding=utf-8 filetype=python ts=4 expandtab
