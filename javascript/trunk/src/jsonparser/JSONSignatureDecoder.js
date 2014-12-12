/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*================================================================*/
/*                       JSONSignatureDecoder                     */
/*================================================================*/

org.webpki.json.JSONSignatureDecoder = function (/* JSONObjectReader */rd) 
{
    var signature = rd.getObject (org.webpki.json.JSONSignatureDecoder.SIGNATURE_JSON);
    var version = signature.getStringConditional (org.webpki.json.JSONSignatureDecoder.VERSION_JSON,
                                                  org.webpki.json.JSONSignatureDecoder.SIGNATURE_VERSION_ID);
    if (version != org.webpki.json.JSONSignatureDecoder.SIGNATURE_VERSION_ID)
    {
        org.webpki.util._error ("Unknown \"" + org.webpki.json.JSONSignatureDecoder.SIGNATURE_JSON + "\" version: " + version);
    }
    this._signature_algorithm = signature.getString (org.webpki.json.JSONSignatureDecoder.ALGORITHM_JSON);
    this._getKeyInfo (signature);
    this._extensions = null;
    if (signature.hasProperty (org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON))
    {
        var ext_arr_reader = signature.getArray (org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON);
        this._extensions = [];
        do
        {
            var ext_obj = ext_arr_reader.getObject ();
            // Minimal syntax check
            ext_obj.getString (org.webpki.json.JSONSignatureDecoder.TYPE_JSON);
            this._extensions.push (ext_obj);
        }
        while (ext_arr_reader.hasMore ());
    }
    this._signature_value = signature.getBinary (org.webpki.json.JSONSignatureDecoder.VALUE_JSON);
    var save = signature.root.property_list;
    var new_list = [];
    for (var i = 0; i < save.length; i++)
    {
        if (save[i].name != org.webpki.json.JSONSignatureDecoder.VALUE_JSON)
        {
            new_list.push (save[i]);
        }
    }
    signature.root.property_list = new_list;
    this._normalized_data = org.webpki.json.JSONObjectWriter._getNormalizedSubset (rd.root);
    if (this._extensions)
    {
        var new_list2 = [];
        for (var i = 0; i < new_list.length; i++)
        {
            if (new_list[i].name != org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON)
            {
                new_list2.push (new_list[i]);
            }
        }
        signature.root.property_list = new_list2;
    }
    signature.checkForUnread ();
    signature.root.property_list = save;
};

org.webpki.json.JSONSignatureDecoder.RSA_PUBLIC_KEY             = "RSA";

org.webpki.json.JSONSignatureDecoder.EC_PUBLIC_KEY              = "EC";


org.webpki.json.JSONSignatureDecoder.ALGORITHM_JSON             = "algorithm";

org.webpki.json.JSONSignatureDecoder.E_JSON                     = "e";

org.webpki.json.JSONSignatureDecoder.EXTENSIONS_JSON            = "extensions";

org.webpki.json.JSONSignatureDecoder.ISSUER_JSON                = "issuer";

org.webpki.json.JSONSignatureDecoder.KEY_ID_JSON                = "keyId";

org.webpki.json.JSONSignatureDecoder.N_JSON                     = "n";

org.webpki.json.JSONSignatureDecoder.CURVE_JSON                 = "curve";

org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON            = "publicKey";

org.webpki.json.JSONSignatureDecoder.SERIAL_NUMBER_JSON         = "serialNumber";

org.webpki.json.JSONSignatureDecoder.SIGNATURE_JSON             = "signature";

org.webpki.json.JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON    = "signerCertificate";

org.webpki.json.JSONSignatureDecoder.VALUE_JSON                 = "value";

org.webpki.json.JSONSignatureDecoder.SIGNATURE_VERSION_ID       = "http://xmlns.webpki.org/jcs/v1";

org.webpki.json.JSONSignatureDecoder.SUBJECT_JSON               = "subject";

org.webpki.json.JSONSignatureDecoder.TYPE_JSON                  = "type";

org.webpki.json.JSONSignatureDecoder.URL_JSON                   = "url";

org.webpki.json.JSONSignatureDecoder.VERSION_JSON               = "version";

org.webpki.json.JSONSignatureDecoder.X_JSON                     = "x";

org.webpki.json.JSONSignatureDecoder.CERTIFICATE_PATH_JSON      = "certificatePath";

org.webpki.json.JSONSignatureDecoder.Y_JSON                     = "y";

/* void */org.webpki.json.JSONSignatureDecoder.prototype._getKeyInfo = function (/* JSONObjectReader */rd)
{
    this._key_id = rd.getStringConditional (org.webpki.json.JSONSignatureDecoder.KEY_ID_JSON);
    if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.CERTIFICATE_PATH_JSON))
    {
        this._readX509CertificateEntry (rd);
    }
    else if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON))
    {
        this._public_key = org.webpki.json.JSONSignatureDecoder._getPublicKey (rd);
    }
    else if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.URL_JSON))
    {
        org.webpki.util._error ("\"" + org.webpki.json.JSONSignatureDecoder.URL_JSON + "\" not yet implemented");
    }
};

/* static Uint8Array */org.webpki.json.JSONSignatureDecoder._getCryptoBinary = function (/* JSONObjectReader */rd, /* String */property)
{
    var crypto_binary = rd.getBinary (property);
    if (crypto_binary[0] == 0x00)
    {
        org.webpki.util._error ("Public key parameters must not contain leading zeroes");
    }
    return crypto_binary;
};

/* Uint8Array */org.webpki.json.JSONSignatureDecoder._getPublicKey = function (/* JSONObjectReader */rd)
{
    rd = rd.getObject (org.webpki.json.JSONSignatureDecoder.PUBLIC_KEY_JSON);
    var public_key = null;
    var type = rd.getString (org.webpki.json.JSONSignatureDecoder.TYPE_JSON);
    if (type == org.webpki.json.JSONSignatureDecoder.RSA_PUBLIC_KEY)
    {
        public_key = org.webpki.crypto.encodeRSAPublicKey 
            (org.webpki.json.JSONSignatureDecoder._getCryptoBinary (rd, org.webpki.json.JSONSignatureDecoder.N_JSON),
             org.webpki.json.JSONSignatureDecoder._getCryptoBinary (rd, org.webpki.json.JSONSignatureDecoder.E_JSON));
    }
    else if (type == org.webpki.json.JSONSignatureDecoder.EC_PUBLIC_KEY)
    {
        public_key = org.webpki.crypto.encodeECPublicKey 
        (rd.getString (org.webpki.json.JSONSignatureDecoder.CURVE_JSON),
         rd.getBinary (org.webpki.json.JSONSignatureDecoder.X_JSON),
         rd.getBinary (org.webpki.json.JSONSignatureDecoder.Y_JSON));
    }
    else
    {
        org.webpki.util._error ("Unknown key type: " + type);
    }
    rd.checkForUnread ();
    return public_key;
};

/* public Uint8Array */org.webpki.json.JSONSignatureDecoder.prototype.getNormalizedData = function ()
{
    return this._normalized_data;
};

/* public Uint8Array */org.webpki.json.JSONSignatureDecoder.prototype.getSignatureValue = function ()
{
    return this._signature_value;
};

/* public String */org.webpki.json.JSONSignatureDecoder.prototype.getSignatureAlgorithm = function ()
{
    return this._signature_algorithm;
};

/* public JSONObjectReader[] */org.webpki.json.JSONSignatureDecoder.prototype.getExtensions = function ()
{
    return this._extensions;
};

/* void */org.webpki.json.JSONSignatureDecoder.prototype._checkRequest = function (/* JSONSignatureTypes */signature_type)
{
    if (signature_type != this.getSignatureType ())
    {
        org.webpki.util._error ("Request doesn't match received signature: " + 
                                org.webpki.json.JSONSignatureTypes.getName (this.getSignatureType ()));
    }
};

org.webpki.json.JSONSignatureDecoder.prototype.verify = function (/* Verifier*/verifier)
{
    if (verifier.getVerifierType () != this.getSignatureType ())
    {
        org.webpki.util._error ("Verifier type doesn't match the received signature");
    }
    if (!verifier.verify (this))
    {
        org.webpki.util._error ("Signature didn't validate");
    }
};

/* public Uint8Array[]/X509Certificate[] */org.webpki.json.JSONSignatureDecoder.prototype.getCertificatePath = function ()
{
    this._checkRequest (org.webpki.json.JSONSignatureTypes.X509_CERTIFICATE);
    return this._certificate_path;
};

/* public Uint8Array/PublicKey */org.webpki.json.JSONSignatureDecoder.prototype.getPublicKey = function ()
{
    if (this.getSignatureType () != org.webpki.json.JSONSignatureTypes.X509_CERTIFICATE)
    {
        this._checkRequest (org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY);
    }
    return this._public_key;
};

/* public String */org.webpki.json.JSONSignatureDecoder.prototype.getKeyId = function ()
{
    return this._key_id;
};

/* public JSONSignatureTypes */org.webpki.json.JSONSignatureDecoder.prototype.getSignatureType = function ()
{
    if (this._certificate_path != null)
    {
        return org.webpki.json.JSONSignatureTypes.X509_CERTIFICATE;
    }
    return this._public_key == null ? org.webpki.json.JSONSignatureTypes.SYMMETRIC_KEY : org.webpki.json.JSONSignatureTypes.ASYMMETRIC_KEY;
};

/* Uint8Array[] */org.webpki.json.JSONSignatureDecoder._getCertificatePath = function (/* JSONObjectReader */rd)
{
    return rd.getBinaryArray (org.webpki.json.JSONSignatureDecoder.CERTIFICATE_PATH_JSON);
/*      
        X509Certificate last_certificate = null;
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        for (byte[] certificate_blob : rd.getBinaryArray (X509_CERTIFICATE_PATH_JSON))
          {
            try
              {
                CertificateFactory cf = CertificateFactory.getInstance ("X.509");
                X509Certificate certificate = (X509Certificate)cf.generateCertificate (new ByteArrayInputStream (certificate_blob));
                certificates.add (pathCheck (last_certificate, last_certificate = certificate));
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        return certificates.toArray (new X509Certificate[0]);
*/
};

/* void */org.webpki.json.JSONSignatureDecoder.prototype._readX509CertificateEntry = function (/* JSONObjectReader */rd)
{
    this._certificate_path = org.webpki.json.JSONSignatureDecoder._getCertificatePath (rd);
    var signature_certificate = new org.webpki.crypto.X509CertificateDecoder (this._certificate_path[0]);
    this._public_key = signature_certificate.public_key;
    if (rd.hasProperty (org.webpki.json.JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON))
    {
        rd = rd.getObject (org.webpki.json.JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON);
        var issuer = rd.getString (org.webpki.json.JSONSignatureDecoder.ISSUER_JSON);
        var serial_number = rd.getBigInteger (org.webpki.json.JSONSignatureDecoder.SERIAL_NUMBER_JSON);
        var subject = rd.getString (org.webpki.json.JSONSignatureDecoder.SUBJECT_JSON);
        if (signature_certificate.issuer != null && signature_certificate.subject != null)
        {
            if (signature_certificate.issuer != issuer ||
                !signature_certificate.serial_number.equals (serial_number) ||
                signature_certificate.subject != subject)
            {
                org.webpki.util._error ("\"" + org.webpki.json.JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON + "\" doesn't match actual certificate");
            }
        }
    }
};
