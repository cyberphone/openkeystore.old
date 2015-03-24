# This is a short program showing a possible CSR using JCS for the
# ACME (Automatic Certificate Management Environment) system

theKey = (
'{'
'  "kty":"EC",'
'  "crv":"P-256",'
'  "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",'
'  "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",'
'  "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"'
'}')

from org.webpki.json import SignatureKey
from org.webpki.json.Writer import JSONObjectWriter

jsonObject = JSONObjectWriter().setString("@context","https://letsencrypt.org/acme/v1").setString("@qualifier","CertificateRequest")
jsonObject.setString("domain","example.com")
jsonObject.setBinary("secret",'\x56\x23\x23\x00\x10');
jsonObject.setSignature(SignatureKey.new(theKey))
print jsonObject.serialize()
