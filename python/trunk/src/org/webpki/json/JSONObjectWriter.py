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

from org.webpki.json import JCSValidator
from org.webpki.json import JCSSignatureKey
from org.webpki.json.Utils import base64UrlEncode

class new:
  def __init__(self,optionalRoot=None):
    if optionalRoot:
      self.root = optionalRoot
    else:
      self.root = OrderedDict()

  def setInt(self,name,value):
    if not isinstance(value,int):
      raise TypeError('Integer expected')
    return self.put(name,value)

  def setString(self,name,value):
    if not isinstance(value,str):
      raise TypeError('String expected')
    return self.put(name,value)

  def setFloat(self,name,value):
    if isinstance(value, int):
      value = float(value)
    elif not isinstance(value,float):
      raise TypeError('Float expected')
    return self.put(name,value)

  def setObject(self,name, optionalRoot=None):
    newObject = new(optionalRoot)
    self.put(name,newObject.root)
    return newObject

  def setBinary(self,name,value):
    if not isinstance(value, str):
      raise TypeError('String or bytearray expected')
    return self.put(name,base64UrlEncode(value))

  def setSignature(self,signatureKey):
    if not isinstance(signatureKey,JCSSignatureKey.new):
      raise TypeError('JCSSignature expected')
    signatureObject = new()
    signatureObject.setString('algorithm',signatureKey.algorithm)
    signatureObject.setObject('publicKey',signatureKey.getPublicKeyParameters())
    self.put('signature',signatureObject.root)
    hashObject = JCSValidator.algorithms[signatureKey.algorithm][1].new(JCSValidator.serialize(self.root).encode("utf-8"))
    if signatureKey.isRSA():
      signer = PKCS1_v1_5.new(signatureKey.nativePrivateKey)
      signatureObject.setBinary("value",signer.sign(hashObject))
    else:
      pass
    return self

  def put(self,name,value):
    if not isinstance(name,str):
      raise TypeError('Name must be a string')
    if name in self.root:
      raise ValueError('Duplicate property: "' + name + '"')
    self.root[name] = value
    return self
    
  def serialize(self):
    return JCSValidator.serialize(self.root)
