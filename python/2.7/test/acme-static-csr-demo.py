# This is a short program showing a possible CSR using JCS for the
# ACME (Automatic Certificate Management Environment) system

# This variation uses a declared rather than programmatic message
 
theKey = (
'{'
'  "kty":"EC",'
'  "crv":"P-256",'
'  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",'
'  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",'
'  "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"'
'}')

from collections import OrderedDict
from org.webpki.json import SignatureKey
from org.webpki.json.Writer import JSONObjectWriter
from org.webpki.json.Utils import base64UrlEncode

message = OrderedDict([
    ("@context"  , "https://letsencrypt.org/acme/v1"),
    ("@qualifier", "CertificateRequest"),
    ("domain"    , "example.com"),
    ("an_object" , OrderedDict([("key1", 5),
                                ("key2","hi")])),
    ("secret"    , base64UrlEncode('\x56\x23\x23\x00\x10'))
])

jsonObject = JSONObjectWriter(message)
jsonObject.setSignature(SignatureKey.new(theKey))
print jsonObject.serialize()
