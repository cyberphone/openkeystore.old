import collections
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512


algorithms = collections.OrderedDict([
   ('RS256', (True, SHA256)),
   ('RS512', (True, SHA512)),
   ('ES256', (False, SHA256)),
   ('ES512', (False, SHA512))
])

def test(algorithm):
  if algorithm in algorithms:
    algorithms[algorithm][1].new()
    return "RSA=" + str(algorithms[algorithm][0]) + ' Algorithm=' + algorithm
  else:
    comma = False
    result = ''
    for item in algorithms:
      if comma:
        result += ', '
      comma = True
      result += item
    return 'Should be one of: ' + result

class MyDict(collections.OrderedDict):
  pass

h = MyDict()

print test("RS67")
print test("ES512")
print test("RS256")

from ecdsa.curves import NIST256p
from ecdsa.util import sigdecode_der
from ecdsa import VerifyingKey
from org.webpki.json.Utils import base64UrlDecode

x = base64UrlDecode("vlYxD4dtFJOp1_8_QUcieWCW-4KrLMmFL2rpkY1bQDs")
y = base64UrlDecode("fxEF70yJenP3SPHM9hv-EnvhG6nXr3_S-fDqoj-F6yM")
value = base64UrlDecode("MEUCIQCorbamxEnAjgMcrKyINItf_Df6q_YMYcBux30r83AISQIgJPZyvK--k6pGL0dcC_kXAfEzuVaKDUx-a-qQIYklBgc")
print len(value)

data = '{"statement":"Hello signed world!","otherProperties":[2000,true],"signature":{"algorithm":"ES256","publicKey":{"type":"EC","curve":"P-256","x":"vlYxD4dtFJOp1_8_QUcieWCW-4KrLMmFL2rpkY1bQDs","y":"fxEF70yJenP3SPHM9hv-EnvhG6nXr3_S-fDqoj-F6yM"}}}'.encode("utf-8")
digest = SHA256.new(data).digest()

vk = VerifyingKey.from_string(x + y, curve=NIST256p)
print vk.verify_digest(value,digest,sigdecode=sigdecode_der)
