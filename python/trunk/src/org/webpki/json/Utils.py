import json
import collections
import base64

from Crypto.Util.number import bytes_to_long

def getCryptoBigNum (base64String):
    return bytes_to_long(base64UrlDecode(base64String))

def base64UrlDecode(data):
    if isinstance(data, unicode):
        try:
            data = data.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError(
                'unicode argument should contain only ASCII characters')
    elif not isinstance(data, str):
        raise TypeError('argument should be a str or unicode')
    return base64.urlsafe_b64decode(data + '=' * (4 - (len(data) % 4)))

