#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: Module for zones table in Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging

from sqlalchemy import text
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy import join
from sqlalchemy.sql.expression import select
from sqlalchemy.dialects.postgresql import *


# Own modules
from . import Base
from .key import TsigKey
from ..namespace import Namespace

LOG = logging.getLogger(__name__)


#------------------------------------------------------------------------------
class Zone(Base):

    __tablename__ = 'zones'

    # Column definitions
    zone_id = Column(
        Integer, nullable=False, server_default=text("nextval('seq_zone_id')"), primary_key=True)
    zone_name = Column(String(250), nullable=False, unique=True)
    master_ns = Column(String(250), nullable=True)
    key_id = Column(Integer, ForeignKey('tsig_keys.key_id', ondelete='RESTRICT'), nullable=False)
    max_hosts = Column(Integer, nullable=True)
    default_min_wait = Column(INTERVAL, nullable=True)
    disabled = Column(BOOLEAN, nullable=False, default=False)
    created = Column(
        DateTime(timezone=True), nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))
    modified = Column(
        DateTime(timezone=True), nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))
    description = Column(Text, nullable=True)

    # -----------------------------------------------------
    def __init__(
        self, zone_id=None, zone_name=None, master_ns=None, key_id=None,
            max_hosts=None, default_min_wait=None,
            disabled=False, created=None, modified=None, description=None):

        self.zone_id = zone_id
        self.zone_name = zone_name
        self.master_ns = master_ns
        self.key_id = key_id
        self.max_hosts = max_hosts
        self.default_min_wait = default_min_wait
        self.disabled = disabled
        self.created = created
        self.modified = modified
        self.description = description

    # -----------------------------------------------------
    def __repr__(self):

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("zone_id=%r" % (self.zone_id))
        fields.append("zone_name=%r" % (self.zone_name))
        fields.append("master_ns=%r" % (self.master_ns))
        fields.append("key_id=%r" % (self.key_id))
        fields.append("max_hosts=%r" % (self.max_hosts))
        fields.append("default_min_wait=%r" % (self.default_min_wait))
        fields.append("disabled=%r" % (self.disabled))

        out += ", ".join(fields) + ")>"
        return out

    # -----------------------------------------------------
    def to_namespace(self, for_json=False):

        zone_ns = Namespace()
        for key in self.__dict__:
            if not key.startswith('_'):
                val = self.__dict__[key]
                setattr(zone_ns, key, val)
        if for_json:
            if self.created:
                zone_ns.created = self.created.isoformat(' ')
            if self.created:
                zone_ns.modified = self.modified.isoformat(' ')
            if self.default_min_wait is not None:
                zone_ns.default_min_wait = self.default_min_wait.total_seconds()
        return zone_ns

#------------------------------------------------------------------------------
class ZoneView(Base):

    __tablename__ = 'v_zones'

    # Column definitions
    zone_id = Column(Integer, nullable=False, primary_key=True)
    zone_name = Column(String(250), nullable=False, unique=True)
    master_ns = Column(String(250), nullable=True)
    key_id = Column(Integer, nullable=False)
    key_name = Column(String(250), nullable=False)
    key_value = Column(String(250), nullable=False)
    max_hosts = Column(Integer, nullable=True)
    default_min_wait = Column(INTERVAL, nullable=True)
    disabled = Column(BOOLEAN, nullable=False, default=False)
    created = Column(DateTime(timezone=True), nullable=False)
    modified = Column(DateTime(timezone=True), nullable=False)
    description = Column(Text, nullable=True)

    # -----------------------------------------------------
    def __init__(
        self, zone_id=None, zone_name=None, master_ns=None, key_id=None,
            key_name=None, key_value=None, max_hosts=None, default_min_wait=None,
            disabled=False, created=None, modified=None, description=None):

        self.zone_id = zone_id
        self.zone_name = zone_name
        self.master_ns = master_ns
        self.key_id = key_id
        self.key_name = key_name
        self.key_value = key_value
        self.max_hosts = max_hosts
        self.default_min_wait = default_min_wait
        self.disabled = disabled
        self.created = created
        self.modified = modified
        self.description = description

    # -----------------------------------------------------
    def __repr__(self):

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("zone_id=%r" % (self.zone_id))
        fields.append("zone_name=%r" % (self.zone_name))
        fields.append("master_ns=%r" % (self.master_ns))
        fields.append("key_id=%r" % (self.key_id))
        fields.append("key_name=%r" % (self.key_name))
        fields.append("max_hosts=%r" % (self.max_hosts))
        fields.append("default_min_wait=%r" % (self.default_min_wait))
        fields.append("disabled=%r" % (self.disabled))

        out += ", ".join(fields) + ")>"
        return out

    # -----------------------------------------------------
    def to_namespace(self, for_json=False):

        zone_ns = Namespace()
        for key in self.__dict__:
            if not key.startswith('_'):
                val = self.__dict__[key]
                setattr(zone_ns, key, val)
        if for_json:
            if self.created:
                zone_ns.created = self.created.isoformat(' ')
            if self.created:
                zone_ns.modified = self.modified.isoformat(' ')
            if self.default_min_wait is not None:
                zone_ns.default_min_wait = self.default_min_wait.total_seconds()
        return zone_ns

    # -----------------------------------------------------
    @classmethod
    def all_zones(cls, enabled=None):

        zones = []

        LOG.debug("Getting all zones ...")

        filters = {}

        if enabled is not None:
            if bool(enabled):
                filters['disabled'] = text('False')
            else:
                filters['disabled'] = text('True')

        q = cls.query.order_by(cls.zone_name)
        if filters:
            q = cls.query.filter(**filters).order_by(cls.zone_name)

        return q.all()



#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
