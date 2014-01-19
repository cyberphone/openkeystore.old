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
/*                            ASN1                                */
/*================================================================*/

org.webpki.asn1.TAGS =
{
    OID                : 0x06,
    SEQUENCE           : 0x30,
    INTEGER            : 0x02,
    NULL               : 0x05,
    BITSTRING          : 0x03,
    EXPLICIT_CONTEXT_0 : 0xA0,
    EXPLICIT_CONTEXT_1 : 0xA1,
    OCTET_STRING       : 0x04
};

org.webpki.asn1.ASN1Object = function (/* byte */tag, /* ASN1Object or Unit8Array */data)
{
    this.data = [];  /* ASN1Object or Unit8Array */
    this.data[0] = data;
    this.tag = tag;
    return this;
};

/* ASN1Object */org.webpki.asn1.ASN1Object.prototype.addData = function (/* ASN1Object or Unit8Array */data)
{
    this.data[this.data.length] = data;
    return this;
};

/* Unit8Array */org.webpki.asn1.ASN1Object.prototype.encode = function ()
{
    this.result = new Uint8Array ();
    if (this.tag == org.webpki.asn1.TAGS.BITSTRING)
    {
        this.update ([0]);  // This implementation doesn't support everything ASN.1...
    }
    for (var i = 0; i < this.data.length; i++)
    {
        if (this.data[i] instanceof org.webpki.asn1.ASN1Object)
        {
            this.update (this.data[i].encode ()); 
        }
        else
        {
            this.update (this.data[i]);
        }
    }
    var payload = this.result;
    var length = payload.length;
    this.result = new Uint8Array ([this.tag, length]);
    if (length > 127)
    {
        this.result[1] = 0x82;
        this.update ([length >> 8]);
        this.update ([length & 0xFF]);
    }
    return this.update (payload);
};

/* Unit8Array */org.webpki.asn1.ASN1Object.prototype.update = function (array)
{
    return this.result = org.webpki.util.ByteArray.add (this.result, array);
};

/* ASN1Object */org.webpki.asn1.ASN1PositiveInteger = function (/* Uint8Array */blob_integer)
{
    if (blob_integer[0] > 127)
    {
        blob_integer = org.webpki.util.ByteArray.add ([0], blob_integer);
    }
    return new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.INTEGER, blob_integer);
};
