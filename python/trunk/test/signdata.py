import sys
import codecs

from org.webpki.json import JSONObjectWriter
from org.webpki.json import JCSSignatureKey

from org.webpki.json.Utils import parseJson

# Our test program
if not len(sys.argv) in (2,3):
    print 'Private-key [JSON-in-file]'
    sys.exit(1)

def readFile(name):
  return codecs.open(name, "r", "utf-8").read()

keyString = readFile(sys.argv[1])
if '-----' in keyString:
  signatureKey = JCSSignatureKey.new(keyString,"PEM")
else:
  signatureKey = JCSSignatureKey.new(keyString) # JWK is default

if signatureKey.isRSA():
  print "RSA key"
else:
  print "EC key"

if len(sys.argv) == 3:
  jsonObject = JSONObjectWriter.new(parseJson(readFile(sys.argv[2])))
else:
  jsonObject = JSONObjectWriter.new()
  jsonObject.setInt("name", 7)

  jsonObject.setString("nam", "f")
  jsonObject.setObject("myo").setString("keyi","meyi").setFloat("fl",1e+5)

jsonObject.setSignature(signatureKey)

print jsonObject.serialize()
