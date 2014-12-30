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

from org.webpki.json.Utils import cryptoBigNumEncode
from org.webpki.json.Utils import cryptoBigNumDecode
from org.webpki.json import JCSValidator

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

###################################################
# JCS (JSON Cleartext Signature) Signature object #
###################################################

class new:
  def __init__(self,privateKeyString, format='JWK'):
    if format == 'JWK':
      jwk = JCSValidator.parse(privateKeyString)
      keyType = jwk['kty']
      if keyType == 'RSA':
        self.nativePrivateKey = RSA.construct([cryptoBigNumDecode(jwk['n']),
                                              cryptoBigNumDecode(jwk['e']),
                                              cryptoBigNumDecode(jwk['d']),
                                              cryptoBigNumDecode(jwk['p']),
                                              cryptoBigNumDecode(jwk['q'])])
        # JWK syntax checking...
        cryptoBigNumDecode(jwk['dp'])
        cryptoBigNumDecode(jwk['dq'])
        cryptoBigNumDecode(jwk['qi'])
      else:
        raise ValueError('Unsupported key type: "' + keyType + '"');
    elif format == 'PEM':
      if ' RSA ' in privateKeyString:
        self.nativePrivateKey = RSA.importKey(privateKeyString)
      else:
        raise TypeError('EC PEM not implemented')
    else:
      raise ValueError('Unsupported key format: "' + format + '"')
    if self.isRSA():
      self.algorithm = 'RS256'
    else:
      self.algorithm = 'ES256'

  def isRSA(self):
    return isinstance(self.nativePrivateKey,RSA._RSAobj)

  def setAlgorithm(self,algorithm):
    pass

  def getPublicKeyParameters(self, JCSFormat=True):
    keyTypeMnemonic = 'type'
    if not JCSFormat:
      keyTypeMnemonic = 'kty'
    publicKeyParameters = OrderedDict()
    if self.isRSA():
      publicKeyParameters[keyTypeMnemonic] = 'RSA'
      publicKeyParameters['n'] = cryptoBigNumEncode(self.nativePrivateKey.n)
      publicKeyParameters['e'] = cryptoBigNumEncode(self.nativePrivateKey.e)
    else:
      publicKeyParameters[keyTypeMnemonic] = 'EC'
    return publicKeyParameters

