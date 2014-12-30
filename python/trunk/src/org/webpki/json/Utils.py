import base64

from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes

def cryptoBigNumDecode(base64String):
  return bytes_to_long(base64UrlDecode(base64String))
  
def cryptoBigNumEncode(bigPostiveNumber):
  return base64UrlEncode(long_to_bytes(bigPostiveNumber))

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

def base64UrlEncode(data):
  if not isinstance(data, str):
    raise TypeError('argument should be str or bytearray')
  return base64.urlsafe_b64encode(data).rstrip('=')
  
def listKeys(dictionary):
  comma = False
  result = ''
  for item in dictionary:
    if comma:
      result += ', '
    comma = True
    result += item
  return result

