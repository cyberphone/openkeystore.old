import json
import collections
import sys
import codecs
import base64
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# The JCS validator
def validateJCS(jsonObject):
    if not isinstance(jsonObject, collections.OrderedDict):
        raise TypeError('You must use "collections.OrderedDict"')
    signatureObject = jsonObject['signature']
    clonedSignatureObject = collections.OrderedDict(signatureObject)
    signatureAlgorithm = signatureObject['algorithm']
    if signatureAlgorithm != 'RS256':
        raise TypeError('Only the "RS256" algorithm is currently supported')
    publicKey = signatureObject['publicKey']
    if publicKey['type'] != 'RSA':
       raise TypeError('Only "RSA" keys currently are supported')
    rsaPublicKey = RSA.construct([getCryptoBigNum(publicKey['n']),getCryptoBigNum(publicKey['e'])])
    rsaVerifier = PKCS1_v1_5.new(rsaPublicKey)
    signatureValue = base64UrlDecode(signatureObject['value'])
    signatureObject.pop('value')
    signatureData = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False).encode("utf-8")
    jsonObject['signature'] = clonedSignatureObject
    return rsaVerifier.verify(SHA256.new(signatureData),signatureValue), rsaPublicKey

def getCryptoBigNum (base64String):
    bigNumber = bytes_to_long(base64UrlDecode(base64String))
    return bigNumber

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

# Our test program
if len(sys.argv) != 2:
    print 'No input file given'
    sys.exit(1)
# There should be a file with utf-8 json in, read and parse it
jsonString = codecs.open(sys.argv[1], "r", "utf-8").read()
# print jsonString
jsonObject = json.loads(jsonString, object_pairs_hook=collections.OrderedDict)
result = validateJCS(jsonObject)
print 'Valid=' + str(result[0]) + ' Key=\n' + result[1].exportKey(format='PEM', passphrase=None, pkcs=1)
