# This is a short program showing a possible CSR using JCS for the
# ACME (Automatic Certificate Management Environment) system.

# Here using a custom signer which for example could be an HSM

from Crypto.Hash import SHA256

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from org.webpki.json.BaseKey import BaseKey
from org.webpki.json.Writer import JSONObjectWriter

theKey = (
'-----BEGIN RSA PRIVATE KEY-----\n'
'MIIEowIBAAKCAQEAqjx6oxpLErZEAlZuuuZi3C65gC7gLJtdW8k2mCCD0vDNAaMu\n'
'YkS7Y9OfAHCFNri5mNojX9Wv+ABl3TIwbCD34InON2dts3s0GgTRjSfIAytl9odd\n'
'6lpRfzT4rarnDwpEBFnMXFcONTaMCHii4nFLkFEQBP+yKg80uul0Zt6K9ebFEe0r\n'
'7Lq0eTCVdapsN0jeUOdTUxX8/3dj3q0vib21ueQdbJrPXNZ28wZYuuJZsKGSGSNE\n'
'Jo7qK+IApiZtSCJzSmrAkb6alLmoVMOVy5rd++aebG7GswQ/Geaqp3DpgP6G4s3l\n'
'BFRi6sQS5vBcSmI4nFKHLutK0Q+HQMkMA7aDRwIDAQABAoIBAFbI0jRH+TGm3XDb\n'
'o0OAo7Ff2I1yWDIlWiiqoTxYhxuIStqk18adB3LStWJB+od1EJjNy+7VPwoNGeDz\n'
'7x+Qhw1e81PnVFOFYYBKKJHvT9Xdz/Mn+0a3mIhi9suCLpzKPPaC2N3SO5oBHs5K\n'
'wa7y1vTRfnst5yPt8JHA5ehzVyAYGdUCubzqTP4d3Av8RbjiugPohPS8GmqxIYHv\n'
'3ufs2T89QzmFQwXVmWpn0/qHJjsHGwI6nwS6Z014GT9inB5RiMlfvHsD1LAyV6YE\n'
'qjLBSyk9btSRMHX7t3uY6tCVnhQdVn1/Q6PochUl00a9/vqE8Z9ZhkiJnyaKo/Z+\n'
'qGLFFqECgYEA31zlo1NEpbZkB7uLDIJZ3xLDP2+Fel3n0P332Ds5UI+cZhX14Hdu\n'
'kK+/7lY6ZhdLsGFbFqTlRgeyPXRDt9jCaF0O2y89mxOSMca5/q9yo9hYaRe0Vuna\n'
'kfsleuZskkFRPYtiGDWLWz5ErIVkCHH+YbGM6tT2q2fYk7U4kGFJodkCgYEAwxxU\n'
'TgvcMqX3djB9DmpYNbuR51CfZalFzIGH9T7D5Fg4R9RdZKC3Lh7aml9MkHJLCBDG\n'
'jyFSA5W7dRqX0goM8YMEOWeW3mcf9IWDtimR9/J7KLvo4Mv/G7GINLkXOy0EDPSf\n'
'0aBGJC5UZTozI7ynHTWf4k7z/yyTgk1Hozzu+h8CgYEAwskAea3j759fHF8wo3gJ\n'
'Z7+1BVz7yfqabmcL/EWpddfHTD9abKW6hfK+LdqEkwM9vlMoXFbwmmGbznvVkj41\n'
'S03b5skLsHEgzMfA65mVH81LTFqfqivFsAiUZtkLVYAgmMs0gGgxXyCuQsUQt0yx\n'
'ygBMI34UnuWwuR8QdNhingECgYBOqT878AAo00y/c7EXfLxvfV3HenOpEuO3HYno\n'
'0BM+HmsiWnYEud7gU0Qi9MTzf4DMkabb0b01AMsA3WXUIoUxYXb0hdUHeWAivylo\n'
'6b2Vz0bkF04+Q0Bos9yMFQtOqkl1x7IfW5SrxZn07c/sWoStfA8nuFkayaf24p09\n'
'LLXUVQKBgDjFqNGi34b0Du1LcWNhHKc1UV8JjvMTXgynfte2BeptG994fXHvFt6G\n'
'+N3RpzlSgNk1QuHLze3qmAOqYfwNR/dXNDmiOIZ2vEb+F8pNvajAR/7A3GVbE/Ex\n'
'WzQhroBt4fEiJusZfznJVTjnzeTmIGxpNTyHMznbVDA9eY+tW1du\n'
'-----END RSA PRIVATE KEY-----\n')

class CustomSigner(BaseKey):
    def __init__(self,privateKeyString,algorithm):
        # Custom constructor
        self.nativePrivateKey = RSA.importKey(privateKeyString)
        self.algorithm = algorithm

    def signData(self,data):
        # Implementation: bare-bones and hard-coded
        return PKCS1_v1_5.new(self.nativePrivateKey).sign(SHA256.new(data))

    def setSignatureMetaData(self,jsonObjectWriter):
        # Implementation: bare-bones and hard-coded
        jsonObjectWriter.setString('algorithm',self.algorithm)
        publicKey = jsonObjectWriter.setObject('publicKey')
        publicKey.setString('type','RSA')
        publicKey.setCryptoBigNum('n',self.nativePrivateKey.n)
        publicKey.setCryptoBigNum('e',self.nativePrivateKey.e)

jsonObject = JSONObjectWriter().setString("@context","https://letsencrypt.org/acme/v1").setString("@qualifier","CertificateRequest")
jsonObject.setString("domain","example.com")
jsonObject.setBinary("secret",b'\x56\x23\x23\x00\x10');
jsonObject.setSignature(CustomSigner(theKey,'RS256')) # Custom init parameters
print (jsonObject.serialize())
