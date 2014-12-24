import json
import collections
import base64

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from org.webpki.json import Utils

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
    self.rsaPublicKey = RSA.construct([Utils.getCryptoBigNum(self.publicKey['n']),Utils.getCryptoBigNum(self.publicKey['e'])])
    rsaVerifier = PKCS1_v1_5.new(self.rsaPublicKey)
    signatureValue = Utils.base64UrlDecode(signatureObject.pop('value'))
    self.normalizedData = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)
    jsonObject['signature'] = clonedSignatureObject
    self.valid = rsaVerifier.verify(SHA256.new(self.normalizedData.encode("utf-8")),signatureValue)

  def isValid(self):
    return self.valid

  def getPublicKey(self,type='PEM'):
    if type == 'Native':
      return self.rsaPublicKey
    elif type == 'PEM':
      return self.rsaPublicKey.exportKey(format='PEM', passphrase=None, pkcs=1)
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

# TODO: "extensions", "version", "keyId" and checks for extranous properties

