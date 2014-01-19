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
/*                        Key Serializing                         */
/*================================================================*/

org.webpki.crypto.SUPPORTED_EC_CURVES = 
[//                 SKS Algorithm ID                             Bits       Textual OID            ASN.1 OID (without header)
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b163",        163,     "1.3.132.0.15",         [0x2B, 0x81, 0x04, 0x00, 0x0F],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b233",        233,     "1.3.132.0.27",         [0x2B, 0x81, 0x04, 0x00, 0x1B],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b283",        283,     "1.3.132.0.17",         [0x2B, 0x81, 0x04, 0x00, 0x11],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p192",        192,     "1.2.840.10045.3.1.1",  [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",        256,     "1.2.840.10045.3.1.7",  [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p384",        384,     "1.3.132.0.34",         [0x2B, 0x81, 0x04, 0x00, 0x22],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p521",        521,     "1.3.132.0.35",         [0x2B, 0x81, 0x04, 0x00, 0x23],
    "http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1", 256,     "1.3.36.3.3.2.8.1.1.7", [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
];

org.webpki.crypto.RSA_ALGORITHM_OID    = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
org.webpki.crypto.EC_ALGORITHM_OID     = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; 

org.webpki.crypto.XML_DSIG_CURVE_PREFIX      = "urn:oid:";

org.webpki.crypto._error = function (/* String */message)
{
    throw "CryptoException: " + message;
};


/* int */org.webpki.crypto.getECParamsFromURI = function (/* String */uri)
{
    if (uri.indexOf (org.webpki.crypto.XML_DSIG_CURVE_PREFIX) == 0)
    {
        var oid = uri.substring (org.webpki.crypto.XML_DSIG_CURVE_PREFIX.length);
        for (var i = 2; i < org.webpki.crypto.SUPPORTED_EC_CURVES.length; i+= 4)
        {
            if (org.webpki.crypto.SUPPORTED_EC_CURVES[i] == oid)
            {
                return i - 2;
            }
        }
    }
    else
    {
        for (var i = 0; i < org.webpki.crypto.SUPPORTED_EC_CURVES.length; i += 4)
        {
            if (org.webpki.crypto.SUPPORTED_EC_CURVES[i] == uri)
            {
                return i;
            }
        }
    }
    org.webpki.crypto._error ("Unsupported EC curve: " + uri);
};

/* Uint8Array */org.webpki.crypto.adjustECCoordinate = function (/* int */params_entry, /* Unit8Array */coordinate)
{
    var length = Math.floor ((org.webpki.crypto.SUPPORTED_EC_CURVES[params_entry + 1] + 7) / 8);
    while (coordinate.length < length)
    {
        coordinate = org.webpki.util.ByteArray.add ([0x00], coordinate);
    }
    return coordinate;
};

/* Uint8Array */org.webpki.crypto.createECPublicKey = function (/* String */url, /* Uint8Array */x, /* Uint8Array */y)
{
    var params_entry = org.webpki.crypto.getECParamsFromURI (url);
    return new org.webpki.asn1.ASN1Object
      (
        org.webpki.asn1.TAGS.SEQUENCE,
          new org.webpki.asn1.ASN1Object
            (
              org.webpki.asn1.TAGS.SEQUENCE,
              new org.webpki.asn1.ASN1Object
                (
                  org.webpki.asn1.TAGS.OID,
                  org.webpki.crypto.EC_ALGORITHM_OID
                )
            )
        .addData 
          (
            new org.webpki.asn1.ASN1Object 
              (
                org.webpki.asn1.TAGS.OID,
                org.webpki.crypto.SUPPORTED_EC_CURVES[params_entry + 3]
              )
          )
      )
    .addData
      (
        new org.webpki.asn1.ASN1Object 
          (
            org.webpki.asn1.TAGS.BITSTRING,
            org.webpki.util.ByteArray.add 
              (
                org.webpki.util.ByteArray.add
                  (
                    [0x04],
                    org.webpki.crypto.adjustECCoordinate (params_entry, x)
                  ), 
                org.webpki.crypto.adjustECCoordinate (params_entry, y)
              )
          )
      ).encode ();
};

/* Uint8Array */org.webpki.crypto.createRSAPublicKey = function (/* Uint8Array */modulus, /* Uint8Array */exponent)
{
    return new org.webpki.asn1.ASN1Object
      (
        org.webpki.asn1.TAGS.SEQUENCE,
          new org.webpki.asn1.ASN1Object
            (
              org.webpki.asn1.TAGS.SEQUENCE,
              new org.webpki.asn1.ASN1Object
                (
                  org.webpki.asn1.TAGS.OID,
                  org.webpki.crypto.RSA_ALGORITHM_OID
                )
            )
        .addData (new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.NULL, []))
      )
    .addData
      (
        new org.webpki.asn1.ASN1Object 
          (
            org.webpki.asn1.TAGS.BITSTRING,
            new org.webpki.asn1.ASN1Object
              (
                org.webpki.asn1.TAGS.SEQUENCE,
                org.webpki.asn1.ASN1PositiveInteger (modulus)
              )
            .addData (org.webpki.asn1.ASN1PositiveInteger (exponent))
          )
      ).encode ();
};
