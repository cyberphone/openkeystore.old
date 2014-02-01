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
/*                       Key Serialization                        */
/*================================================================*/

//* Serialization/de-serialization of X.509 SPKIs + rudimentary X.509 certificate decoder

org.webpki.crypto.SUPPORTED_NAMED_CURVES = 
[//                 SKS Algorithm ID                   Coordinate Length   Textual OID            ASN.1 OID (without header)
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b163",        21,     "1.3.132.0.15",         [0x2B, 0x81, 0x04, 0x00, 0x0F],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b233",        30,     "1.3.132.0.27",         [0x2B, 0x81, 0x04, 0x00, 0x1B],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.b283",        36,     "1.3.132.0.17",         [0x2B, 0x81, 0x04, 0x00, 0x11],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p192",        24,     "1.2.840.10045.3.1.1",  [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",        32,     "1.2.840.10045.3.1.7",  [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p384",        48,     "1.3.132.0.34",         [0x2B, 0x81, 0x04, 0x00, 0x22],
    "http://xmlns.webpki.org/sks/algorithm#ec.nist.p521",        66,     "1.3.132.0.35",         [0x2B, 0x81, 0x04, 0x00, 0x23],
    "http://xmlns.webpki.org/sks/algorithm#ec.secg.p256k1",      32,     "1.3.132.0.10",         [0x2B, 0x81, 0x04, 0x00, 0x0A],
    "http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1", 32,     "1.3.36.3.3.2.8.1.1.7", [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
];

org.webpki.crypto.RSA_ALGORITHM_OID    = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
org.webpki.crypto.EC_ALGORITHM_OID     = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; 

org.webpki.crypto.XML_DSIG_CURVE_PREFIX      = "urn:oid:";

/* int */org.webpki.crypto._getECParamsFromURI = function (/* String */uri)
{
    if (uri.indexOf (org.webpki.crypto.XML_DSIG_CURVE_PREFIX) == 0)
    {
        var oid = uri.substring (org.webpki.crypto.XML_DSIG_CURVE_PREFIX.length);
        for (var i = 2; i < org.webpki.crypto.SUPPORTED_NAMED_CURVES.length; i+= 4)
        {
            if (org.webpki.crypto.SUPPORTED_NAMED_CURVES[i] == oid)
            {
                return i - 2;
            }
        }
    }
    else
    {
        for (var i = 0; i < org.webpki.crypto.SUPPORTED_NAMED_CURVES.length; i += 4)
        {
            if (org.webpki.crypto.SUPPORTED_NAMED_CURVES[i] == uri)
            {
                return i;
            }
        }
    }
    org.webpki.util._error ("Unsupported EC curve: " + uri);
};

/* Uint8Array */org.webpki.crypto.leftPadWithZeros = function (/* int */required_length, /* Unit8Array */original)
{
    if (original.length > required_length)
    {
        org.webpki.util._error ("Input data out of bounds: " + original.length);        
    }
    while (original.length < required_length)
    {
        original = org.webpki.util.ByteArray.add ([0x00], original);
    }
    return original;
};

/* Uint8Array */org.webpki.crypto.encodeECPublicKey = function (/* String */url, /* Uint8Array */x, /* Uint8Array */y)
{
    var params_entry = org.webpki.crypto._getECParamsFromURI (url);
    var coordinate_length = org.webpki.crypto.SUPPORTED_NAMED_CURVES[params_entry + 1];
    return new org.webpki.asn1.ASN1Encoder
      (
        org.webpki.asn1.TAGS.SEQUENCE,
        new org.webpki.asn1.ASN1Encoder
          (
            org.webpki.asn1.TAGS.SEQUENCE,
            new org.webpki.asn1.ASN1Encoder
              (
                org.webpki.asn1.TAGS.OID,
                org.webpki.crypto.EC_ALGORITHM_OID
              )
          )
        .addComponent 
          (
            new org.webpki.asn1.ASN1Encoder 
              (
                org.webpki.asn1.TAGS.OID,
                org.webpki.crypto.SUPPORTED_NAMED_CURVES[params_entry + 3]
              )
          )
      )
    .addComponent
      (
        new org.webpki.asn1.ASN1Encoder 
          (
            org.webpki.asn1.TAGS.BITSTRING,
            org.webpki.util.ByteArray.add 
              (
                [0x00, 0x04],
                org.webpki.util.ByteArray.add
                  (
                    org.webpki.crypto.leftPadWithZeros (coordinate_length, x),
                    org.webpki.crypto.leftPadWithZeros (coordinate_length, y)
                  )
              )
          )
      ).encode ();
};

/* ASN1Encoder */org.webpki.crypto.createASN1PositiveInteger = function (/* Uint8Array */blob_integer)
{
    if (blob_integer[0] > 127)
    {
        blob_integer = org.webpki.util.ByteArray.add ([0], blob_integer);
    }
    return new org.webpki.asn1.ASN1Encoder (org.webpki.asn1.TAGS.INTEGER, blob_integer);
};

/* Uint8Array */org.webpki.crypto.encodeRSAPublicKey = function (/* Uint8Array */modulus, /* Uint8Array */exponent)
{
    return new org.webpki.asn1.ASN1Encoder
      (
        org.webpki.asn1.TAGS.SEQUENCE,
        new org.webpki.asn1.ASN1Encoder
          (
            org.webpki.asn1.TAGS.SEQUENCE,
            new org.webpki.asn1.ASN1Encoder
              (
                org.webpki.asn1.TAGS.OID,
                org.webpki.crypto.RSA_ALGORITHM_OID
              )
          )
        .addComponent (new org.webpki.asn1.ASN1Encoder (org.webpki.asn1.TAGS.NULL, []))
      )
    .addComponent
      (
        new org.webpki.asn1.ASN1Encoder 
          (
            org.webpki.asn1.TAGS.BITSTRING,
            org.webpki.util.ByteArray.add 
              (
                [0],
                new org.webpki.asn1.ASN1Encoder
                  (
                    org.webpki.asn1.TAGS.SEQUENCE,
                    org.webpki.crypto.createASN1PositiveInteger (modulus)
                  )
                .addComponent (org.webpki.crypto.createASN1PositiveInteger (exponent)).encode ()
              )
          )
      ).encode ();
};

/* Public Key Data */org.webpki.crypto.PublicKeyDecoder = function (/* Uint8Array */spki)
{
    var outer_sequence = new org.webpki.asn1.ASN1SequenceDecoder (spki);
    if (outer_sequence.numberOfComponents () != 2)
    {
        org.webpki.util._error ("SubjectPublicKeyInfo sequence must be two elements");        
    }
    var algorithm_id = outer_sequence.getComponent (0).getASN1Sequence ();
    if (algorithm_id.numberOfComponents () != 2)
    {
        org.webpki.util._error ("Algorithm ID sequence must be two elements");        
    }
    var public_key_type = algorithm_id.getComponent (0).getASN1ObjectIDRawData ();
    var encapsulated_key = outer_sequence.getComponent (1).getASN1BitString (true);
    if ((this.rsa_flag = org.webpki.util.ByteArray.equals (public_key_type, org.webpki.crypto.RSA_ALGORITHM_OID)))
    {
        algorithm_id.getComponent (1).getASN1NULL ();
        var rsa_params = new org.webpki.asn1.ASN1SequenceDecoder (encapsulated_key);
        if (rsa_params.numberOfComponents () != 2)
        {
            org.webpki.util._error ("RSA parameter sequence must be two elements");        
        }
        this.modulus = rsa_params.getComponent (0).getASN1PositiveInteger ();
        this.exponent = rsa_params.getComponent (1).getASN1PositiveInteger ();
    }
    else if (org.webpki.util.ByteArray.equals (public_key_type, org.webpki.crypto.EC_ALGORITHM_OID))
    {
        if (encapsulated_key[0] != 0x04)
        {
            org.webpki.util._error ("EC uncompressed parameter expected");        
        }
        var ec_curve = algorithm_id.getComponent (1).getASN1ObjectIDRawData ();
        for (var i = 3; i < org.webpki.crypto.SUPPORTED_NAMED_CURVES.length; i += 4)
        {
            if (org.webpki.util.ByteArray.equals (org.webpki.crypto.SUPPORTED_NAMED_CURVES[i], ec_curve))
            {
                var coordinate_length = org.webpki.crypto.SUPPORTED_NAMED_CURVES[i - 2];
                if (encapsulated_key.length != coordinate_length * 2 + 1)
                {
                    org.webpki.util._error ("ECPoint length error");        
                }
                this.x = new Uint8Array (encapsulated_key.subarray (1, 1 + coordinate_length));
                this.y = new Uint8Array (encapsulated_key.subarray (1 + coordinate_length));
                this.uri = org.webpki.crypto.SUPPORTED_NAMED_CURVES[i - 3];
                this.oid = org.webpki.crypto.SUPPORTED_NAMED_CURVES[i - 1];
                return;
            }
        }
        org.webpki.util._error ("EC curve OID unknown");        
    }
    else
    {
        org.webpki.util._error ("Public key OID unknown");        
    }
};

org.webpki.crypto.X500_ATTRIBUTES = 
    [// Symbolic       ASN.1 OID (without header)
        "CN",       [0x55, 0x04, 0x03],
        "DC",       [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19],
        "OU",       [0x55, 0x04, 0x0B],
        "O",        [0x55, 0x04, 0x0A],
        "L",        [0x55, 0x04, 0x07],
        "ST",       [0x55, 0x04, 0x08],
        "STREET",   [0x55, 0x04, 0x09],
        "C",        [0x55, 0x04, 0x06]
    ];

/* String */org.webpki.crypto.getAttributeString = function (asn1_type)
{
    var string = "";
    var data = asn1_type.getBodyData ();
    for (var i = 0; i < data.length; i++)
    {
        var b = data[i];
        if (asn1_type.tag == org.webpki.asn1.TAGS.UTF8STRING && b > 127)
        {
            var b2 = data[++i];
            if ((b & 0x20) == 0) // Two byters
            {
                var c = String.fromCharCode (((b & 0x1F) << 6) | (b2 & 0x3F));
            }
            else  // Three byters
            {
                var b3 = data[++i];
                var c = String.fromCharCode (((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F));
            }
        }
        else if (asn1_type.tag == org.webpki.asn1.TAGS.BMPSTRING)
        {
            var c = String.fromCharCode ((b << 8) | data[++i]);
        }
        else
        {
            var c = String.fromCharCode (b);
        }
        if (c == ',' || c == ';' || c == '+' || c == '=' || c == '\\')
        {
            string += '\\';
        }
        string += c;
    }
    return string;
};

/* String */org.webpki.crypto.getDistinguishedName = function (asn1_sequence)
{
    var dn_holder = asn1_sequence.getASN1Sequence ();
    var dn = "";
    var next = false;
    var q = dn_holder.numberOfComponents ();
    while (--q >= 0)
    {
        if (next)
        {
            dn += ',';
        }
        else
        {
            next = true;
        }
        var set = dn_holder.getComponent (q).getASN1Set ();
        if (set.numberOfComponents () != 1)
        {
console.debug ("Multivalued, drop it");
            return null;
        }
        var attr = set.getComponent (0).getASN1Sequence ();
        if (attr.numberOfComponents () != 2)
        {
console.debug ("Weird, drop it");
            return null;
        }
        // Now it seems that we can try to do something sensible!
        var attr_name = attr.getComponent (0).getASN1ObjectIDRawData ();
        var non_symbolic = true;
        for (var i = 1; i < org.webpki.crypto.X500_ATTRIBUTES.length; i += 2)
        {
            if (org.webpki.util.ByteArray.equals (attr_name, org.webpki.crypto.X500_ATTRIBUTES[i]))
            {
                non_symbolic = false;
                dn += org.webpki.crypto.X500_ATTRIBUTES[i - 1] + '=' + org.webpki.crypto.getAttributeString (attr.getComponent (1));
                break;
            }
        }
        if (non_symbolic)
        {
            var i = 0;
            var oid = null;
            while (i < attr_name.length)
            {
                var subid = 0;
                do
                {
                    subid = (subid << 7) + (attr_name[i] &0x7F);
                }
                while ((attr_name[i++] & 0x80) != 0);
                if (oid == null)
                {
                    oid = (Math.floor (subid / 40)).toString ();
                    subid = Math.floor (subid % 40);
                }
                oid += '.' + subid;
            }
            dn += oid + '=#' + org.webpki.util.ByteArray.toHex (attr.getComponent (1).encode ());
        }
    }
    return dn;
};

/* Certificate Data */org.webpki.crypto.X509CertificateDecoder = function(/* Uint8Array */certificate_blob)
{
    var asn1 = new org.webpki.asn1.ASN1SequenceDecoder (certificate_blob);
    var tbs = asn1.getComponent (0).getASN1Sequence ();
    var index = 0;
    if (tbs.getComponent (0).getTag () == org.webpki.asn1.TAGS.EXPLICIT_CONTEXT_0)
    {
        index++;  // V3
    }
    this.serial_number = new org.webpki.math.BigInteger (tbs.getComponent (index++).getASN1PositiveInteger ());
    tbs.getComponent (index++).getASN1Sequence ();  // Signature alg, skip
    this.issuer = org.webpki.crypto.getDistinguishedName (tbs.getComponent (index++));
    if (this.issuer === undefined)
    {
        console.debug ("Couldn't decode issuer DN");
    }
    if (tbs.getComponent (index++).getASN1Sequence ().numberOfComponents () != 2)
    {
        org.webpki.util._error ("Certificate validity not found");        
    }
    this.subject = org.webpki.crypto.getDistinguishedName (tbs.getComponent (index++));
    if (this.subject === undefined)
    {
        console.debug ("Couldn't decode subject DN");
    }
    new org.webpki.crypto.PublicKeyDecoder (this.public_key = tbs.getComponent (index).getASN1Sequence ().encode ());
};
