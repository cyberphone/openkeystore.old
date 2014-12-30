import simplejson as json
from collections import OrderedDict
from decimal import Decimal

from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from ecdsa.curves import NIST256p
from ecdsa.curves import NIST384p
from ecdsa.curves import NIST521p
from ecdsa.util import sigdecode_der
from ecdsa import VerifyingKey

from org.webpki.json.Utils import cryptoBigNumDecode
from org.webpki.json.Utils import base64UrlDecode
from org.webpki.json.Utils import listKeys

algorithms = OrderedDict([
   ('RS256', (True,  SHA256)),
   ('RS384', (True,  SHA384)),
   ('RS512', (True,  SHA512)),
   ('ES256', (False, SHA256)),
   ('ES384', (False, SHA384)),
   ('ES512', (False, SHA512))
])

ecCurves = OrderedDict([
   ('P-256', NIST256p),
   ('P-384', NIST384p),
   ('P-521', NIST521p)
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
      raise TypeError('Found "' + signatureAlgorithm + '". Supported algorithms: ' + listKeys(algorithms))
    hashObject = algorithms[signatureAlgorithm][1].new(serialize(jsonObject).encode("utf-8"))
    jsonObject['signature'] = clonedSignatureObject
    self.publicKey = signatureObject['publicKey']
    self.keyType = self.publicKey['type']
    if algorithms[signatureAlgorithm][0]:
      if self.keyType != 'RSA':
        raise TypeError('"RSA" expected')
      self.nativePublicKey = RSA.construct([cryptoBigNumDecode(self.publicKey['n']),
                                            cryptoBigNumDecode(self.publicKey['e'])])
      if not PKCS1_v1_5.new(self.nativePublicKey).verify(hashObject,signatureValue):
        raise ValueError('Invalid Signature!')
    else:
      if self.keyType != 'EC':
        raise TypeError('"EC" expected')
      ecCurve = self.publicKey['curve']
      if not ecCurve in ecCurves:
        raise TypeError('Found "' + ecCurve + '". Supported EC curves: ' + listKeys(ecCurves))
      self.nativePublicKey = VerifyingKey.from_string(base64UrlDecode(self.publicKey['x']) + 
                                                      base64UrlDecode(self.publicKey['y']),
                                                      curve=ecCurves[ecCurve])
      self.nativePublicKey.verify_digest(signatureValue,hashObject.digest(),sigdecode=sigdecode_der)
      
  def getPublicKey(self,type='PEM'):
    if type == 'PEM':
      if self.keyType == 'RSA':
        return self.nativePublicKey.exportKey(format='PEM') + '\n'
      else:
        return self.nativePublicKey.to_pem()
    elif type == 'Native':
      return self.nativePublicKey
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

