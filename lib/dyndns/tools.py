#!/usr/bin/env python


import pprint
import copy
import re
import locale

from six import PY2, PY3

RE_YES = re.compile(r'^\s*(?:y(?:es)?|true)\s*$', re.IGNORECASE)
RE_NO = re.compile(r'^\s*(?:no?|false|off)\s*$', re.IGNORECASE)
PAT_TO_BOOL_TRUE = locale.nl_langinfo(locale.YESEXPR)
RE_TO_BOOL_TRUE = re.compile(PAT_TO_BOOL_TRUE)
PAT_TO_BOOL_FALSE = locale.nl_langinfo(locale.NOEXPR)
RE_TO_BOOL_FALSE = re.compile(PAT_TO_BOOL_FALSE)



# =============================================================================
def pp(data, indent=4, width=120):
    p = pprint.PrettyPrinter(indent=indent, width=width)
    return p.pformat(data)

# =============================================================================
def to_unicode(obj, encoding='utf-8'):
    """Transforms a string, which is not a unicode string, into a unicode string."""
    do_decode = False
    if PY2:
        if isinstance(obj, str):
            do_decode = True
    else:
        if isinstance(obj, bytes):
            do_decode = True

    if do_decode:
        obj = obj.decode(encoding)

    return obj

# =============================================================================
def encode_or_bust(obj, encoding='utf-8'):
    """Encodes the given unicode object into the given encoding."""
    do_encode = False
    if PY2:
        if isinstance(obj, unicode):
            do_encode = True
    else:
        if isinstance(obj, str):
            do_encode = True

    if do_encode:
        obj = obj.encode(encoding)

    return obj

# =============================================================================
def to_bytes(obj, encoding='utf-8'):
    "Wrapper for encode_or_bust()"
    return encode_or_bust(obj, encoding)


# =============================================================================
def to_str(obj, encoding='utf-8'):
    """
    Transformes the given string-like object into the str-type according
    to the current Python version.
    """

    if PY2:
        return encode_or_bust(obj, encoding)
    else:
        return to_unicode(obj, encoding)

# =============================================================================
def encode_struct(struct, encoding='utf-8'):
    result = None
    if isinstance(struct, list):
        result = []
        for item in struct:
            result.append(encode_struct(item, encoding))
    elif isinstance(struct, dict):
        result = {}
        for key in struct.keys():
            new_key = to_str(key, encoding)
            val = encode_struct(struct[key], encoding)
            result[new_key] = val
    else:
        result = to_str(struct, encoding)
    return result


# =============================================================================
def to_bool(value):
    """
    Converter from string to boolean values (e.g. from configurations)
    """

    if not value:
        return False

    try:
        v_int = int(value)
    except ValueError:
        pass
    except TypeError:
        pass
    else:
        if v_int == 0:
            return False
        else:
            return True

    global PAT_TO_BOOL_TRUE
    global RE_TO_BOOL_TRUE
    global PAT_TO_BOOL_FALSE
    global RE_TO_BOOL_FALSE

    c_yes_expr = locale.nl_langinfo(locale.YESEXPR)
    if c_yes_expr != PAT_TO_BOOL_TRUE:
        PAT_TO_BOOL_TRUE = c_yes_expr
        RE_TO_BOOL_TRUE = re.compile(PAT_TO_BOOL_TRUE)
    # log.debug("Current pattern for 'yes': %r.", c_yes_expr)

    c_no_expr = locale.nl_langinfo(locale.NOEXPR)
    if c_no_expr != PAT_TO_BOOL_FALSE:
        PAT_TO_BOOL_FALSE = c_no_expr
        RE_TO_BOOL_FALSE = re.compile(PAT_TO_BOOL_FALSE)
    # log.debug("Current pattern for 'no': %r.", c_no_expr)

    v_str = ''
    if isinstance(value, str):
        v_str = value
        if PY2:
            if isinstance(value, unicode):
                v_str = value.encode('utf-8')
    elif PY3 and isinstance(value, bytes):
        v_str = value.decode('utf-8')
    else:
        v_str = str(value)

    match = RE_YES.search(v_str)
    if match:
        return True
    match = RE_TO_BOOL_TRUE.search(v_str)
    if match:
        return True

    match = RE_NO.search(v_str)
    if match:
        return False
    match = RE_TO_BOOL_FALSE.search(v_str)
    if match:
        return False

    return bool(value)



# =============================================================================

if __name__ == "__main__":
    pass

# =============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
