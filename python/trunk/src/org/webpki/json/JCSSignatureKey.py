from collections import OrderedDict

from Crypto.PublicKey import RSA

from ecdsa.util import sigdecode_der
from ecdsa import SigningKey

from org.webpki.json.Utils import base64UrlEncode
from org.webpki.json.Utils import base64UrlDecode
from org.webpki.json.Utils import cryptoBigNumEncode
from org.webpki.json.Utils import cryptoBigNumDecode
from org.webpki.json.Utils import parseJson
from org.webpki.json.Utils import getEcCurveName
from org.webpki.json.Utils import getEcCurve

###################################################
# JCS (JSON Cleartext Signature) Signature object #
###################################################

class new:
  def __init__(self,privateKeyString, format='JWK'):
    if format == 'JWK':
      jwk = parseJson(privateKeyString)
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
      elif keyType == 'EC':
        self.nativePrivateKey = SigningKey.from_string(base64UrlDecode(jwk['d']),getEcCurve(jwk['crv']))
      else:
        raise ValueError('Unsupported key type: "' + keyType + '"');
    elif format == 'PEM':
      if ' RSA ' in privateKeyString:
        self.nativePrivateKey = RSA.importKey(privateKeyString)
      else:
        self.nativePrivateKey = SigningKey.from_pem(privateKeyString)
    else:
      raise ValueError('Unsupported key format: "' + format + '"')
    if self.isRSA():
      self.algorithm = 'RS256'
    else:
      self.algorithm = 'ES256'

  def isRSA(self):
    return isinstance(self.nativePrivateKey,RSA._RSAobj)

  def setAlgorithm(self,algorithm):
    if not algorithm in algorithms:
      pass

  def getPublicKeyParameters(self, JCSFormat=True):
    keyTypeMnemonic = 'type'
    curveMnemonic = 'curve'
    if not JCSFormat:
      keyTypeMnemonic = 'kty'
      curveMnemonic = 'crv'
    publicKeyParameters = OrderedDict()
    if self.isRSA():
      publicKeyParameters[keyTypeMnemonic] = 'RSA'
      publicKeyParameters['n'] = cryptoBigNumEncode(self.nativePrivateKey.n)
      publicKeyParameters['e'] = cryptoBigNumEncode(self.nativePrivateKey.e)
    else:
      publicKeyParameters[keyTypeMnemonic] = 'EC'
      publicKeyParameters[curveMnemonic] = getEcCurveName(self.nativePrivateKey)
      point = self.nativePrivateKey.get_verifying_key().to_string()
      length = len(point)
      if length % 2:
        raise ValueError('EC point length error')
      length >>= 1
      publicKeyParameters['x'] = base64UrlEncode(point[:length])
      publicKeyParameters['y'] = base64UrlEncode(point[length:])
    return publicKeyParameters

