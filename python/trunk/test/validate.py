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
          print 'Valid=' + str(validator.isValid()) + ' Normalized data=\n' + validator.getNormalizedData()

class EnhancedDecimal(Decimal):
   def __str__ (self):
     return self.saved_string

   def __new__(cls, value="0", context=None):
     obj = Decimal.__new__(cls,value,context)
     obj.saved_string = value
     return obj;

#jsonObject = json.loads(jsonString, object_pairs_hook=collections.OrderedDict,parse_float=EnhancedDecimal)
jsonObject = JCSValidator.parse(jsonString)
result = JCSValidator.new(jsonObject)
print 'Valid=' + str(result.isValid())
if result.isValid():
  print 'Key=' + result.getPublicKey(type='JWK')
#  print result.getNormalizedData () # Fails on Windows unless you have the "Lucida Console" font

checkAllSignatures(jsonObject)

