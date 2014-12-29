import simplejson as json
import collections
from decimal import Decimal

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from org.webpki.json.Utils import getCryptoBigNum
from org.webpki.json.Utils import base64UrlDecode

############################################
# JCS (JSON Cleartext Signature) validator #
############################################

class new:

  def __init__(self,jsonObject):
    if not isinstance(jsonObject, collections.OrderedDict):
      raise TypeError('JCS requires JSON to be parsed into a "collections.OrderedDict"')
    signatureObject = jsonObject['signature']
    clonedSignatureObject = collections.OrderedDict(signatureObject)
    signatureAlgorithm = signatureObject['algorithm']
    if signatureAlgorithm != 'RS256':
      raise TypeError('Only the "RS256" algorithm is currently supported')
    self.publicKey = signatureObject['publicKey']
    if self.publicKey['type'] != 'RSA':
      raise TypeError('Only "RSA" keys are currently supported')
    self.rsaPublicKey = RSA.construct([getCryptoBigNum(self.publicKey['n']),getCryptoBigNum(self.publicKey['e'])])
    rsaVerifier = PKCS1_v1_5.new(self.rsaPublicKey)
    signatureValue = base64UrlDecode(signatureObject.pop('value'))
    self.normalizedData = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)
    jsonObject['signature'] = clonedSignatureObject
    self.valid = rsaVerifier.verify(SHA256.new(self.normalizedData.encode("utf-8")),signatureValue)

  def isValid(self):
    return self.valid

  def getPublicKey(self,type='PEM'):
    if type == 'PEM':
      return self.rsaPublicKey.exportKey(format='PEM')
    elif type == 'Native':
      return self.rsaPublicKey
    elif type == 'JWK':
      jwk = collections.OrderedDict()
      for item in self.publicKey:
        key = item
        if key == 'type':
          key = 'kty'
        jwk[key] = self.publicKey[item]
      return json.dumps(jwk,separators=(',',':'),ensure_ascii=False)
    elif type == 'JCS':
      return json.dumps(self.publicKey,separators=(',',':'),ensure_ascii=False)
    else:
      raise ValueError('Unknown key type: "' + type + '"') 

  def getNormalizedData(self):
    return self.normalizedData

############################################
# JCS Compatible Parser                    #
############################################

def parse(jsonString):
  return json.loads(jsonString, object_pairs_hook=collections.OrderedDict,parse_float=EnhancedDecimal)

# Support class
class EnhancedDecimal(Decimal):
   def __str__ (self):
     return self.saved_string

   def __new__(cls, value="0", context=None):
     obj = Decimal.__new__(cls,value,context)
     obj.saved_string = value
     return obj;  

# TODO: "extensions", "version", "keyId" and checks for extranous properties

