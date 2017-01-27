#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: Module for config table in Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging
import uuid
import re
import datetime

# Third party modules
try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

from sqlalchemy import text
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.dialects.postgresql import *
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.schema import MetaData


# Own modules
from ..constants import PASSWD_RESTRICTIONS_MIN_LEN
from ..constants import PASSWD_RESTRICTIONS_SMALL_CHARS_REQUIRED
from ..constants import PASSWD_RESTRICTIONS_CAPITALS_REQUIRED
from ..constants import PASSWD_RESTRICTIONS_DIGITS_REQUIRED
from ..constants import PASSWD_RESTRICTIONS_SPECIAL_CHARS_REQUIRED

from . import Base, metadata

from ..namespace import Namespace
from ..tools import pp, to_bool
from ..errors import ConfigNotFoundError

LOG = logging.getLogger(__name__)


#------------------------------------------------------------------------------
config_type = ENUM(
    'bool', 'int', 'float', 'str', 'uuid', 'version',
    'date', 'date_tz', 'time', 'timestamp', 'timestamp_tz', 'time_diff',
    metadata=metadata)


#------------------------------------------------------------------------------
class Config(Base):

    __tablename__ = 'config'

    # Column definitions
    cfg_name = Column(String(250), nullable=False, primary_key=True)
    cfg_type = Column(config_type, nullable=True)
    cfg_value = Column(String(250), nullable=True)
    created = Column(
        DateTime(timezone=True), nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))
    modified = Column(
        DateTime(timezone=True), nullable=False,
        server_default=text('CURRENT_TIMESTAMP'))
    description = Column(Text, nullable=True)

    hex_re = re.compile(r'^\s*0?x([0-9a-f]+)\s*$', re.IGNORECASE)
    oct_re = re.compile(r'^\s*0?o([0-7]+)\s*$', re.IGNORECASE)

    d_pat = r'(\d+-\d+-\d+)'
    t_pat = r'(\d+:\d+:\d+)([+\-]\d{4})?'
    date_pat = r'^\s*' + d_pat + r'\s*$'
    time_pat = r'^\s*' + t_pat + r'\s*$'
    datetime_pat = r'^\s*' + d_pat + r'[T\s]' + t_pat + r'\s*$'
    date_re = re.compile(date_pat)
    time_re = re.compile(time_pat)
    datetime_re = re.compile(datetime_pat)

    d_pat = r'(\d+)\s*d(?:ays?)?'
    s_pat = r'(\d+)(?:\s*s|secs?|seconds?)?'
    td_pat = r'^\s*(?:'
    # days only - group 1
    td_pat += d_pat + r'|'
    # optional days before and seconds - groups 2 and 3
    td_pat += r'(?:' + d_pat + r')?\s*' + s_pat
    # closing regex
    td_pat += r')\s*$'

    td_re = re.compile(td_pat, re.IGNORECASE)

    # -----------------------------------------------------
    def __init__(
        self, cfg_name=None, cfg_type=None, cfg_value=None,
            created=None, modified=None, description=None):

        self.cfg_name = cfg_name
        self.cfg_type = cfg_type
        self.cfg_value = cfg_value
        self.created = created
        self.modified = modified
        self.description = description

    # -----------------------------------------------------
    def __repr__(self):

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("cfg_name=%r" % (self.cfg_name))
        fields.append("cfg_type=%r" % (self.cfg_type))
        fields.append("cfg_value=%r" % (self.cfg_value))

        out += ", ".join(fields) + ")>"
        return out

    # -----------------------------------------------------
    def to_namespace(self):

        user_ns = Namespace()
        for key in self.__dict__:
            if not key.startswith('_'):
                val = self.__dict__[key]
                setattr(user_ns, key, val)
        return user_ns

    # -----------------------------------------------------
    @classmethod
    def all_configs(cls):

        keys = []

        LOG.debug("Getting all config parameters ...")

        q = cls.query.order_by(Config.cfg_name)
        LOG.debug("SQL statement: {}".format(q))

        return q.all()

    # -----------------------------------------------------
    @classmethod
    def get(cls, cfg_name):

        LOG.debug("Searching configuration {!r} ...".format(cfg_name))

        q = cls.query.filter(cls.cfg_name == str(cfg_name))
        LOG.debug("SQL statement: {}".format(q))

        configs = q.all()
        if not configs:
            raise ConfigNotFoundError(cfg_name)

        cfg = configs[0]
        return cls.cast_from_value(cfg.cfg_value, cfg.cfg_type)

    # -----------------------------------------------------
    @classmethod
    def get_password_restrictions(cls):

        passwd_restrictions = {
            'min_len': PASSWD_RESTRICTIONS_MIN_LEN,
            'small_chars_required': PASSWD_RESTRICTIONS_SMALL_CHARS_REQUIRED,
            'capitals_required': PASSWD_RESTRICTIONS_CAPITALS_REQUIRED,
            'digits_required': PASSWD_RESTRICTIONS_DIGITS_REQUIRED,
            'special_chars_required': PASSWD_RESTRICTIONS_SPECIAL_CHARS_REQUIRED,
        }

        cfg_keys = []
        for key in passwd_restrictions.keys():
            cfg_keys.append('passwd_restrict_' + key)

        q = cls.query.filter(cls.cfg_name.in_(cfg_keys))
        LOG.debug("SQL statement: {}".format(q))

        for cfg in q.all():
            val = cfg.cfg_value
            try:
                val = cls.cast_from_value(cfg.cfg_value, cfg.cfg_type)
            except ValueError as e:
                LOG.error("Could not cast cfg value {k} into {t!r}: {v!r}".format(
                    k=cfg.cfg_name, t=cfg.cfg_type, v=cfg.cfg_value))
            key = cfg.cfg_name.replace('passwd_restrict_', '')
            passwd_restrictions[key] = val

        LOG.debug("Got password resrictions:\n{}".format(pp(passwd_restrictions)))

        return passwd_restrictions

    # -----------------------------------------------------
    @classmethod
    def cast_from_value(cls, value, cfg_type):
        """
        Tries to cast the given value into the given type.

        @raise ValueError: if the cast was not successful.
        """

        LOG.debug("Trying to cast {v!r} into {t!r} ...".format(
            v=value, t=cfg_type))

        if cfg_type is None or cfg_type == 'str' or cfg_type == 'version':
            return value

        if cfg_type == 'bool':
            return to_bool(value)

        if cfg_type == 'int':
            base = 10
            match = cls.hex_re.search(value)
            if match:
                return int(match.group(1), 16)
            match = cls.oct_re.search(value)
            if match:
                return int(match.group(1), 8)
            return int(value)

        if cfg_type == 'float':
            return float(value)

        if cfg_type == 'uuid':
            return uuid.UUID(value)

        # Must be in the format '%Y-%m-%d'
        if cfg_type == 'date':
            return datetime.datetime.strptime(value.strip(), '%Y-%m-%d').date()

        if cfg_type == 'time':
            return datetime.datetime.strptime(value.strip(), '%H:%M:%S').time()

        if cfg_type == 'time_tz':
            return datetime.datetime.strptime(value.strip(), '%H:%M:%S%z').time()

        if cfg_type == 'timestamp':
            match = cls.datetime_re.search(value)
            if match:
                p_str = match.group(1) + ' ' + match.group(2)
                return datetime.datetime.strptime(p_str, '%Y-%m-%d %H:%M:%S')
            raise ValueError("Invalid timestamp value {!r} found.".format(value))

        if cfg_type == 'timestamp_tz':
            match = cls.datetime_re.search(value)
            if match:
                p_str = match.group(1) + ' ' + match.group(2)
                if match.group(3):
                    p_str += match.group(3)
                else:
                    p_str += '+0000'
                return datetime.datetime.strptime(p_str, '%Y-%m-%d %H:%M:%S%z')
            raise ValueError("Invalid timestamp value {!r} found.".format(value))

        if cfg_type == 'time_diff':
            days = 0
            secs = 0
            match = cls.td_re.search(value)
            if match:
                if match.group(1) is None:
                    if match.group(2) is not None:
                        days = int(match.group(2))
                    secs = int(match.group(3))
                else:
                    days = int(match.group(1))
                return datetime.timedelta(days, secs)
            raise ValueError("Invalid time_diff value {!r} found.".format(value))

        raise TypeError("Invalid configuration type {!r} found.".format(cfg_type))

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
