var mySigner = function ()
{
};

mySigner.prototype.getAlgorithm = function ()
{
    return this._algorithm;
};

mySigner.prototype.getSignatureType = function ()
{
    return this._signature_type;
};

mySigner.prototype.getPublicKey = function ()
{
    return this._public_key;
};

mySigner.prototype.signData = function (data)
{
    return new Uint8Array (data);
};


var signer = new mySigner ();
signer._algorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
signer._signature_type = org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY;
signer._public_key = org.webpki.util.Base64URL.decode ('MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGRgbhKB9Mw1lDKJFMbD_H\
sBvHR9235X7zF2SxHkDiOWKzGmrFLHoAASZl-Avkd69Lrt6N-b_gdywHzzdNRpxyw');


var signedDoc = new org.webpki.json.JSONObjectWriter ();
signedDoc.setString ("Statement", "Hello \u20acsigned world!");
signedDoc.setSignature (signer);
console.debug (signedDoc.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT));

console.debug ("Signature tests successful!");
