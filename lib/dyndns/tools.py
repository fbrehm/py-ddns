#!/usr/bin/env python


import pprint
import copy

from six import PY2, PY3


# =============================================================================
def pp(data, indent=4):
    p = pprint.PrettyPrinter(indent=indent)
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

if __name__ == "__main__":
    pass

# =============================================================================

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
