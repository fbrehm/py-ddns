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

from sqlalchemy import orm, text
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.dialects.postgresql import *
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.schema import MetaData


# Own modules
from ..constants import CONFIG

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
    td_pat += r'(?:' + d_pat + r'\s*,?)?\s*' + s_pat
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

        self.finish_init()

    # -----------------------------------------------------
    @orm.reconstructor
    def init_on_load(self):
        """Substitution for __init__() in case of loading from a query."""

        self.finish_init()

    # -----------------------------------------------------
    def finish_init(self):

        if getattr(self, 'intialized', False):
            return

        self.valid = False
        self.default = None
        self.value = self.cfg_value
        self.value_for_json = self.cfg_value

        if self.cfg_name and self.cfg_name in CONFIG:
            self.valid = True
            cfg_type = CONFIG[self.cfg_name]['type']
            self.cfg_type = cfg_type
            self.default = CONFIG[self.cfg_name]['default']
            if not self.description and 'description' in CONFIG[self.cfg_name]:
                self.description = CONFIG[self.cfg_name]['description']
            try:
                self.value = self.cast_from_value(self.cfg_value, cfg_type)
                self.value_for_json = self.cast_from_value(
                    self.cfg_value, cfg_type, for_json=True)
            except (ValueError, TypeError) as e:
                LOG.error("Invalid value {v!r} for configuration {k!r} as type {t!r}: {e}".format(
                    v=self.cfg_value, k=self.cfg_name, t=cfg_type, e=e))
                self.valid = False

        self.intialized = True

    # -----------------------------------------------------
    def __repr__(self):

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("cfg_name=%r" % (self.cfg_name))
        fields.append("cfg_type=%r" % (self.cfg_type))
        fields.append("cfg_value=%r" % (self.cfg_value))
        fields.append("valid=%r" % (self.valid))
        fields.append("value=%r" % (self.value))

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
    def all_valid_configs(cls):

        keys = sorted(CONFIG.keys(), key=str.lower)
        c = {}
        configs = []
        for cfg in cls.all_configs():
            if cfg.valid:
                cname = cfg.cfg_name
                c[cname] = cfg
        for cname in keys:
            if cname in c:
                cfg = c[cname]
            else:
                description = None
                if 'description' in CONFIG[cname]:
                    description = CONFIG[cname]['description']
                cfg = cls(
                    cfg_name=cname,
                    cfg_type=CONFIG[cname]['type'],
                    cfg_value=CONFIG[cname]['default'],
                    description=description,
                )
                cfg.valid = True
            configs.append(cfg)

        return configs

    # -----------------------------------------------------
    @classmethod
    def _get(cls, cfg_name):

        if cfg_name not in CONFIG:
            raise ConfigNotFoundError(cfg_name)

        LOG.debug("Searching configuration {!r} ...".format(cfg_name))

        q = cls.query.filter(cls.cfg_name == str(cfg_name))
        LOG.debug("SQL statement: {}".format(q))

        configs = q.all()
        if not configs:
            return None

        return configs[0]

    # -----------------------------------------------------
    @classmethod
    def get(cls, cfg_name):

        if cfg_name not in CONFIG:
            raise ConfigNotFoundError(cfg_name)

        cfg = cls._get(cfg_name)
        if not cfg:
            cfg_type = CONFIG[cfg_name]['type']
            description = None
            if 'description' in CONFIG[cfg_name]:
                description = CONFIG[cfg_name]['description']
            cfg = cls(
                cfg_name=cfg_name,
                cfg_type=CONFIG[cfg_name]['type'],
                cfg_value=CONFIG[cfg_name]['default'],
                description=description,
            )

        return cfg

    # -----------------------------------------------------
    @classmethod
    def get_password_restrictions(cls):

        passwd_restrictions = {
            'min_len': CONFIG['passwd_restrict_min_len']['default'],
            'small_chars_required': CONFIG['passwd_restrict_small_chars_required']['default'],
            'capitals_required': CONFIG['passwd_restrict_capitals_required']['default'],
            'digits_required': CONFIG['passwd_restrict_digits_required']['default'],
            'special_chars_required': CONFIG['passwd_restrict_special_chars_required']['default'],
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
    def get_with_default(cls, cfg_name, default=None):

        val = default
        try:
            val = cls.get(cfg_name)
        except ConfigNotFoundError:
            pass
        return val

    # -----------------------------------------------------
    @classmethod
    def get_debug(cls):

        return cls.get('debug')

    # -----------------------------------------------------
    @classmethod
    def set(cls, cfg_name, value, description=None):

        if cfg_name not in CONFIG:
            raise ConfigNotFoundError(cfg_name)

        cfg_type = CONFIG[cfg_name]['type']

        v = str(value)

        LOG.info("Setting config parameter {p!r} to {v!r} ...".format(
            p=cfg_name, v=value))

        db_session = cls.__session__
        params = {
            'cfg_name': cfg_name,
            'cfg_type': cfg_type,
            'cfg_value': v
        }
        if description is not None:
            params['description'] = str(description)

        LOG.debug("Adding key: {}".format(pp(params)))
        cfg = cls(**params)

        try:
            db_session.add(cls)
            db_session.commit()
        except IntegrityError as e:
            updates = {
                'cfg_value': v,
                'modified': text('CURRENT_TIMESTAMP'),
            }
            if description is not None:
                updates['description'] = str(description)
            q = db_session.query(cls).filter(
                cls.cfg_name == cfg_name)
            LOG.debug("Update query:\n{}".format(q))
            q.update(updates, synchronize_session=False)
            db_session.commit()

        return v

    # -----------------------------------------------------
    @classmethod
    def cast_from_value(cls, value, cfg_type, for_json=False):
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
            d = datetime.datetime.strptime(value.strip(), '%Y-%m-%d').date()
            if for_json:
                return d.strftime('%Y-%m-%d')
            else:
                return d

        if cfg_type == 'time':
            d = datetime.datetime.strptime(value.strip(), '%H:%M:%S').time()
            if for_json:
                return d.strftime('%H:%M:%S')
            else:
                return d

        if cfg_type == 'time_tz':
            d = datetime.datetime.strptime(value.strip(), '%H:%M:%S%z').time()
            if for_json:
                return d.strftime('%H:%M:%S%z')
            else:
                return d

        if cfg_type == 'timestamp':
            match = cls.datetime_re.search(value)
            if match:
                p_str = match.group(1) + ' ' + match.group(2)
                d = datetime.datetime.strptime(p_str, '%Y-%m-%d %H:%M:%S')
                if for_json:
                    return d.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    return d
            raise ValueError("Invalid timestamp value {!r} found.".format(value))

        if cfg_type == 'timestamp_tz':
            match = cls.datetime_re.search(value)
            if match:
                p_str = match.group(1) + ' ' + match.group(2)
                if match.group(3):
                    p_str += match.group(3)
                else:
                    p_str += '+0000'
                d = datetime.datetime.strptime(p_str, '%Y-%m-%d %H:%M:%S%z')
                if for_json:
                    return d.strftime('%Y-%m-%d %H:%M:%S%z')
                else:
                    return d
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
                d = datetime.timedelta(days, secs)
                if for_json:
                    return "{d!d} days, {s!d} seconds".format(
                        d=d.days, s=d.seconds)
                else:
                    return d
            raise ValueError("Invalid time_diff value {!r} found.".format(value))

        raise TypeError("Invalid configuration type {!r} found.".format(cfg_type))

    # -----------------------------------------------------
    @classmethod
    def cast_to_value(cls, value, cfg_type):
        """
        Reverse of cast_from_value().
        Tries to cast the given value into a appropriate str
        to store it in database.

        """

        LOG.debug("Trying to cast {v!r} from {t!r} into str ...".format(
            v=value, t=cfg_type))

        if cfg_type is None:
            return None
        if cfg_type in (
                'str', 'version', 'bool', 'int', 'float', 'uuid'):
            return str(value)

        if cfg_type == 'date':
            d = None
            if isinstance(value, str):
                d = cls.cast_from_value(value, 'date')
            elif isinstance(value, datetime.date):
                d = value
            elif isinstance(value, datetime.datetime):
                d = value.date()
            else:
                raise ValueError("Invalid value {!r} for a date.".format(value))
            return d.strftime('%Y-%m-%d')

        if cfg_type == 'time':
            t = None
            if isinstance(value, str):
                t = cls.cast_from_value(value, 'time')
            elif isinstance(value, datetime.time):
                t = value
            elif isinstance(value, datetime.datetime):
                t = value.time()
            else:
                raise ValueError("Invalid value {!r} for a time.".format(value))
            return t.strftime('%H:%M:%S')

        if cfg_type == 'time_tz':
            t = None
            if isinstance(value, str):
                t = cls.cast_from_value(value, 'time_tz')
            elif isinstance(value, datetime.time):
                t = value
            elif isinstance(value, datetime.datetime):
                t = value.time()
            else:
                raise ValueError("Invalid value {!r} for a time with timezone.".format(value))
            return t.strftime('%H:%M:%S%z')

        if cfg_type == 'timestamp':
            d = None
            if isinstance(value, str):
                d = cls.cast_from_value(value, 'timestamp')
            elif isinstance(value, datetime.datetime):
                d = value
            else:
                raise ValueError("Invalid value {!r} for a timestamp.".format(value))
            return d.strftime('%Y-%m-%d %H:%M:%S')

        if cfg_type == 'timestamp_tz':
            d = None
            if isinstance(value, str):
                d = cls.cast_from_value(value, 'timestamp_tz')
            elif isinstance(value, datetime.datetime):
                d = value
            else:
                raise ValueError("Invalid value {!r} for a timestamp with timezone.".format(value))
            return d.strftime('%Y-%m-%d %H:%M:%S%z')

        if cfg_type == 'time_diff':
            d = None
            if isinstance(value, str):
                d = cls.cast_from_value(value, 'time_diff')
            elif isinstance(value, datetime.timedelta):
                d = value
            else:
                raise ValueError("Invalid value {!r} for a time_diff.".format(value))
            return "{d!d} days, {s!d} seconds".format(d=d.days, s=d.seconds)

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
