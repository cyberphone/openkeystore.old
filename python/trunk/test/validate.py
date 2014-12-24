import json
import collections
import sys
import codecs
from org.webpki.json import JCSValidator

# Our test program
if len(sys.argv) != 2:
    print 'No input file given'
    sys.exit(1)

# There should be a file with utf-8 json in, read and parse it
jsonString = codecs.open(sys.argv[1], "r", "utf-8").read()

# print jsonString

def checkAllSignatures(jsonObject):
    for w in jsonObject:
       if w == 'signature':
          validator = JCSValidator.new(jsonObject)
          print 'Valid=' + str(validator.isValid()) + ' Normalized data=\n' + validator.getNormalizedData()
       if isinstance(jsonObject[w],collections.OrderedDict):
         checkAllSignatures(jsonObject[w])

jsonObject = json.loads(jsonString, object_pairs_hook=collections.OrderedDict)
result = JCSValidator.new(jsonObject)
print 'Valid=' + str(result.isValid())
if result.isValid():
  print 'Key=' + str(result.getPublicKey().exportKey(format='PEM', passphrase=None, pkcs=1))
#  print result.getNormalizedData () # Fails on Windows unless you have the "Lucida Console" font

# checkAllSignatures(jsonObject)

