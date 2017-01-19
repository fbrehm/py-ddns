#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Frank Brehm
@contact: frank@brehm-online.com
@copyright: © 2017 by Frank Brehm, Berlin
@summary: Module for users table in Python DynDNS application
"""
from __future__ import absolute_import

# Standard modules
import os
import logging
import uuid

# Third party modules
try:
    from flask import _app_ctx_stack as stack
except ImportError:
    from flask import _request_ctx_stack as stack

from sqlalchemy import text
from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.dialects.postgresql import *
from sqlalchemy.exc import SQLAlchemyError


# Own modules
from . import Base
from ..namespace import Namespace
from ..tools import pp

LOG = logging.getLogger(__name__)


#------------------------------------------------------------------------------
class User(Base):

    __tablename__ = 'users'

    # Column definitions
    user_id = Column(
        UUID, nullable=False, server_default=text('uuid_generate_v4()'),
        primary_key=True)
    user_name = Column(String(50), nullable=False, unique=True)
    full_name = Column(String(250), nullable=True)
    email = Column(String(250), nullable=False)
    passwd = Column(String(250), nullable=False)
    is_admin = Column(BOOLEAN, nullable=False, default=False)
    is_sticky = Column(BOOLEAN, nullable=False, default=False)
    max_hosts = Column(INTEGER, nullable=True, default=3, server_default=text('3'))
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
        self, user_id=None, user_name=None, full_name=None, email=None,
            passwd=None, is_admin=False, is_sticky=False, max_hosts=3,
            disabled=False, created=None, modified=None, description=None):

        self.user_id = user_id
        self.user_name = user_name
        self.full_name = full_name
        self.email = email
        self.passwd = passwd
        self.is_admin = is_admin
        self.is_sticky = is_sticky
        self.max_hosts = max_hosts
        self.disabled = disabled
        self.created = created
        self.modified = modified
        self.description = description

    # -----------------------------------------------------
    def __repr__(self):

        out = "<%s(" % (self.__class__.__name__)

        fields = []
        fields.append("user_id=%r" % (self.user_id))
        fields.append("user_name=%r" % (self.user_name))
        fields.append("full_name=%r" % (self.full_name))
        fields.append("email=%r" % (self.email))
        fields.append("is_admin=%r" % (self.is_admin))
        fields.append("disabled=%r" % (self.disabled))

        out += ", ".join(fields) + ")>"
        return out

    # -----------------------------------------------------
    def to_namespace(self):

        user_ns = Namespace()
        for key in self.__dict__:
            if not key.startswith('_'):
                val = self.__dict__[key]
                if key == 'user_id':
                    val = uuid.UUID(val)
                setattr(user_ns, key, val)
        return user_ns

    # -----------------------------------------------------
    @classmethod
    def all_users(cls, enabled=None, admin=None):

        keys = []

        LOG.debug("Getting all users ...")

        filters = {}

        if enabled is not None:
            if bool(enabled):
                filters['disabled'] = text('False')
            else:
                filters['disabled'] = text('True')

        if admin is not None:
            if bool(enabled):
                filters['is_admin'] = text('True')
            else:
                filters['is_admin'] = text('False')

        q = cls.query.order_by(User.user_name)
        if filters:
            q = cls.query.filter(**filters).order_by(User.user_name)
        LOG.debug("SQL statement: {}".format(q))

        return q.all()

    # -----------------------------------------------------
    @classmethod
    def get_user(cls, user_ident):

        LOG.debug("Searching user by {!r} ...".format(user_ident))
        user_id = None
        if isinstance(user_ident, uuid.UUID):
            user_id = user_ident
        else:
            try:
                user_id = uuid.UUID(user_ident)
            except ValueError:
                pass

        user = None
        q = None
        if user_id:
            user_id = str(user_id)
            LOG.debug("Searching user by user_id {!r} ...".format(user_id))
            q = cls.query.filter(cls.user_id == user_id)
        else:
            LOG.debug("Searching user by user_name {!r} ...".format(str(user_ident)))
            user = cls.query.filter(cls.user_name == str(user_ident)).first()
            q = cls.query.filter(cls.user_name == str(user_ident))
        LOG.debug("SQL statement: {}".format(q))
        user = q.first()

        return user

    # -----------------------------------------------------
    @classmethod
    def update_user(cls, user_id, updates):

        if not isinstance(updates, dict):
            raise TypeError("Parameter 'updates' must be a dict.")

        db_session = cls.__session__
        if 'user_id' in updates:
            del updates['user_id']

        if updates.keys():
            updates['modified'] = text('CURRENT_TIMESTAMP')
            LOG.debug("Updating user with:\n{}".format(pp(updates)))
            user = cls(**updates)
            uid = str(user_id)
            try:
                q = db_session.query(cls).filter(
                    cls.user_id == uid)
                LOG.debug("Update query:\n{}".format(q))
                q.update(updates, synchronize_session=False)
#                db_session.query(cls).filter(
#                    cls.user_id == user_id).update(
#                    updates, synchronize_session=False)
                db_session.commit()

            except SQLAlchemyError as e:
                db_session.rollback()
                info = {
                    'status': 500,
                    'response': 'Could not change data of user {!r}.'.format(
                        str(user_id)),
                    'errors': [str(e)],
                }
                LOG.error("{c} updating data of user {i}: {e}\nUpdate data:\n{u}".format(
                    c=e.__class__.__name__, i=user_id, e=e, u=pp(updates)))
                return info

        user = cls.get_user(user_id)
        info = {
            'status': 'OK',
            'response': 'Updated user {!r}.'.format(str(user_id)),
            'user': None,
        }
        info['user'] = user.to_namespace().__dict__
        LOG.debug("Found updated user:\n{}".format(pp(info)))
        return info

#==============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
