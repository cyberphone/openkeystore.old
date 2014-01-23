var mySigner = function (signature_type, algorithm)
{
    this._signature_type = signature_type;
    this._algorithm = algorithm;
};

mySigner.prototype.getAlgorithm = function ()
{
    return this._algorithm;
};

/* JSONSignatureTypes */mySigner.prototype.getSignatureType = function ()
{
    return this._signature_type;
};

mySigner.prototype.getPublicKey = function ()
{
    return this._public_key = org.webpki.util.Base64URL.decode ("" + AntCrypto.getPublicKey (this._algorithm));
};

mySigner.prototype.getKeyID = function ()
{
    return "mykey";
};

mySigner.prototype.signData = function (data)
{
    return new Uint8Array (org.webpki.util.Base64URL.decode ("" + AntCrypto.signData (org.webpki.util.Base64URL.encode (data), this._algorithm)));
};

function myVerifier (signer)
{
    this._signer = signer;  // For _testing_purposes_ this is ok, right? :-)
}

/* JSONSignatureTypes */myVerifier.prototype.getVerifierType = function ()
{
    return this._signer._signature_type;
};

/* JSONSignatureTypes */myVerifier.prototype.verify = function (/* JSONSignatureDecoder */signature_decoder)
{
    console.debug (signature_decoder.getSignatureAlgorithm ());
    if (signature_decoder.getSignatureType () == org.webpki.json.JSONSignatureTypes.SYMMETRIC_KEY)
    {
        var signature_key = "";
    }
    else
    {
        var signature_key = org.webpki.util.Base64URL.encode (signature_decoder.getPublicKey ());
//        console.debug (getSignatureAlgorithm ());
//        AntCrypto.verify (signature_decoder.getSignatureAlgorithm ())
    }
    return AntCrypto.verifySignature (org.webpki.util.Base64URL.encode (signature_decoder.getCanonicalizedData ()),
                                      org.webpki.util.Base64URL.encode (signature_decoder.getSignatureValue ()),
                                      signature_decoder.getSignatureAlgorithm (),
                                      signature_key);
};

function signatureTest (signature_type, algorithm)
{
    var signer = new mySigner (signature_type, algorithm);
    var signedDoc = new org.webpki.json.JSONObjectWriter ();
    signedDoc.setString ("Statement", "Hello \u20acsigned world!");
    signedDoc.setSignature (signer);
    var result = signedDoc.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT);
    console.debug (result);
    var document_reader = org.webpki.json.JSONParser.parse (result);
    document_reader.getSignature ().verify (new myVerifier (signer));
}

signatureTest (org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY,
               "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");

signatureTest (org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY,
               "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");

signatureTest (org.webpki.json.JSONSignatureTypes.SYMMETRIC_KEY,
               "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");

console.debug ("Signature tests successful!");
