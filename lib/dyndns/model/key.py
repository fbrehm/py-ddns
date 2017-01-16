#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: Module for tsig_keys table in Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging

# Third party modules

from sqlalchemy import text
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.dialects.postgresql import *


# Own modules
from . import Base
from ..namespace import Namespace
from . import db_session

LOG = logging.getLogger(__name__)


#------------------------------------------------------------------------------
class TsigKey(Base):

    __tablename__ = 'tsig_keys'

    # Column definitions
    key_id = Column(
        INTEGER, nullable=False, server_default=text("nextval('seq_key_id')"),
        primary_key=True)
    key_name = Column(String(250), nullable=False)
    key_value = Column(String(250), nullable=False)
    disabled = Column(BOOLEAN, nullable=False, default=False)
    created = Column(
        DateTime(timezone=True), nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))
    description = Column(Text, nullable=True)

    # -----------------------------------------------------
    def __init__(
        self, key_id=None, key_name=None, key_value=None, disabled=False,
            created=None, description=None):

        self.key_id = key_id
        self.key_name = key_name
        self.key_value = key_value
        self.disabled = disabled
        self.created = created
        self.description = description

    # -----------------------------------------------------
    def __repr__(self):

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("key_id=%r" % (self.key_id))
        fields.append("key_name=%r" % (self.key_name))
        fields.append("key_value=%r" % (self.key_value))
        fields.append("disabled=%r" % (self.disabled))

        out += ", ".join(fields) + ")>"
        return out

    # -----------------------------------------------------
    def to_namespace(self):

        key_ns = Namespace()
        for key in self.__dict__:
            if not key.startswith('_'):
                val = self.__dict__[key]
                setattr(key_ns, key, val)
        return key_ns

    # -----------------------------------------------------
    @classmethod
    def all_keys(cls):

        keys = []

        LOG.debug("Getting all TSIG keys ...")
        for key in cls.query.all():
            keys.append(key)

        return keys

    # -----------------------------------------------------
    @classmethod
    def get_key(cls, key_ident):

        key_id = None
        try:
            key_id = int(key_ident)
        except ValueError:
            pass

        key = None
        if key_id:
            key_id = str(key_id)
            LOG.debug("Searching TSIG key by key_id {!r} ...".format(key_id))
            key = cls.query.filter(cls.key_id == key_id).first()
        else:
            LOG.debug("Searching TSIG key by key name {!r} ...".format(str(key_ident)))
            key = cls.query.filter(cls.key_name == str(key_ident)).first()

        return key


#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
