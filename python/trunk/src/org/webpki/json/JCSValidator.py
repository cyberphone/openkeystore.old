import simplejson as json
from collections import OrderedDict
from decimal import Decimal

from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from org.webpki.json.Utils import getCryptoBigNum
from org.webpki.json.Utils import base64UrlDecode

algorithms = OrderedDict([
   ('RS256', (True,  SHA256)),
   ('RS384', (True,  SHA384)),
   ('RS512', (True,  SHA512)),
   ('ES256', (False, SHA256)),
   ('ES384', (False, SHA384)),
   ('ES512', (False, SHA512))
])

############################################
# JCS (JSON Cleartext Signature) validator #
############################################

class new:
  def __init__(self,jsonObject):
    if not isinstance(jsonObject, OrderedDict):
      raise TypeError('JCS requires JSON to be parsed into a "OrderedDict"')
    signatureObject = jsonObject['signature']
    clonedSignatureObject = OrderedDict(signatureObject)
    signatureValue = base64UrlDecode(signatureObject.pop('value'))
    signatureAlgorithm = signatureObject['algorithm']
    if not signatureAlgorithm in algorithms:
      comma = False
      result = ''
      for item in algorithms:
        if comma:
          result += ', '
        comma = True
        result += item
      raise TypeError('Found "' + signatureAlgorithm + '". Recognized algorithms: ' + result)
    hashObject = algorithms[signatureAlgorithm][1].new(serialize(jsonObject).encode("utf-8"))
    self.publicKey = signatureObject['publicKey']
    keyType = self.publicKey['type']
    if algorithms[signatureAlgorithm][0]:
      if keyType != 'RSA':
        raise TypeError('"RSA" expected')
      self.rsaPublicKey = RSA.construct([getCryptoBigNum(self.publicKey['n']),getCryptoBigNum(self.publicKey['e'])])
      rsaVerifier = PKCS1_v1_5.new(self.rsaPublicKey)
      if not rsaVerifier.verify(hashObject,signatureValue):
        raise ValueError('Invalid Signature!')
    else:
      if keyType != 'EC':
        raise TypeError('"EC" expected')
      raise TypeError('Only "RSA" keys are currently supported')
    jsonObject['signature'] = clonedSignatureObject

  def getPublicKey(self,type='PEM'):
    if type == 'PEM':
      return self.rsaPublicKey.exportKey(format='PEM')
    elif type == 'Native':
      return self.rsaPublicKey
    elif type == 'JWK':
      jwk = OrderedDict()
      for item in self.publicKey:
        key = item
        if key == 'type':
          key = 'kty'
        jwk[key] = self.publicKey[item]
      return serialize(jwk)
    elif type == 'JCS':
      return serialize(self.publicKey)
    else:
      raise ValueError('Unknown key type: "' + type + '"') 


############################################
# JCS Compatible Parser                    #
############################################

def parse(jsonString):
  return json.loads(jsonString, object_pairs_hook=OrderedDict,parse_float=EnhancedDecimal)

############################################
# JCS Compatible Serializer                #
############################################

def serialize(jsonObject):
  return json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)

# Support class
class EnhancedDecimal(Decimal):
   def __str__ (self):
     return self.saved_string

   def __new__(cls, value="0", context=None):
     obj = Decimal.__new__(cls,value,context)
     obj.saved_string = value
     return obj;  

# TODO: "extensions", "version", "keyId" and checks for extranous properties

