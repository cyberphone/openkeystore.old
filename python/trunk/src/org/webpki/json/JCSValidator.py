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
        raise TypeError('You must use "collections.OrderedDict"')
    signatureObject = jsonObject['signature']
    clonedSignatureObject = collections.OrderedDict(signatureObject)
    signatureAlgorithm = signatureObject['algorithm']
    if signatureAlgorithm != 'RS256':
        raise TypeError('Only the "RS256" algorithm is currently supported')
    publicKey = signatureObject['publicKey']
    if publicKey['type'] != 'RSA':
       raise TypeError('Only "RSA" keys are currently supported')
    self.rsaPublicKey = RSA.construct([Utils.getCryptoBigNum(publicKey['n']),Utils.getCryptoBigNum(publicKey['e'])])
    rsaVerifier = PKCS1_v1_5.new(self.rsaPublicKey)
    signatureValue = Utils.base64UrlDecode(signatureObject['value'])
    signatureObject.pop('value')
    signatureData = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False).encode("utf-8")
    jsonObject['signature'] = clonedSignatureObject
    self.valid = rsaVerifier.verify(SHA256.new(signatureData),signatureValue)

  def isValid(self):
    return self.valid

  def getPublicKey(self):
    return self.rsaPublicKey

# TODO: "extensions", "version", "keyId" and checks for extranous properties

