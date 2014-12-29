import simplejson as json
import collections
import sys
import codecs
from decimal import Decimal

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
       if isinstance(jsonObject[w],collections.OrderedDict):
         checkAllSignatures(jsonObject[w])
       if w == 'signature':
          validator = JCSValidator.new(jsonObject)
          print 'Key=' + validator.getPublicKey('JWK')

jsonObject = JCSValidator.parse(jsonString)
JCSValidator.new(jsonObject)
print 'Valid'

checkAllSignatures(jsonObject)

