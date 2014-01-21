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

org.webpki.asn1._error = function (/* String */message)
{
    throw "ASN1Exception: " + message;
};

org.webpki.asn1.ASN1Object = function (/* byte */tag, /* ASN1Object or Unit8Array */argument)
{
    this.components = [];  /* ASN1Object or Unit8Array */
    this.components[0] = argument;
    this.tag = tag;
    return this;
};

/* ASN1Object */org.webpki.asn1.ASN1Object.prototype.addComponent = function (/* ASN1Object */component)
{
    this.components[this.components.length] = component;
    return this;
};

/* Unit8Array */org.webpki.asn1.ASN1Object.prototype.encode = function ()
{
    this.encoded = new Uint8Array ();
    if (this.tag == org.webpki.asn1.TAGS.BITSTRING)
    {
        this.update ([0]);  // This implementation doesn't support everything ASN.1...
    }
    for (var i = 0; i < this.components.length; i++)
    {
        if (this.components[i] instanceof org.webpki.asn1.ASN1Object)
        {
            this.update (this.components[i].encode ()); 
        }
        else
        {
            this.update (this.components[i]);
        }
    }
    var body = this.encoded;
    var length = body.length;
    this.encoded = new Uint8Array ([this.tag, length & 0x7F]);
    if (length > 127)
    {
        if (length > 255)
        {
            this.encoded[1] = 0x82;
            this.update ([length >> 8]);
        }
        else
        {
            this.encoded[1] = 0x81;
        }
        this.update ([length & 0xFF]);
    }
    return this.update (body);
};

/* Unit8Array */org.webpki.asn1.ASN1Object.prototype.update = function (array)
{
    return this.encoded = org.webpki.util.ByteArray.add (this.encoded, array);
};

/* ASN1Object */org.webpki.asn1.ASN1PositiveInteger = function (/* Uint8Array */blob_integer)
{
    if (blob_integer[0] > 127)
    {
        blob_integer = org.webpki.util.ByteArray.add ([0], blob_integer);
    }
    return new org.webpki.asn1.ASN1Object (org.webpki.asn1.TAGS.INTEGER, blob_integer);
};

/* ParsedASN1Object */org.webpki.asn1.ParsedASN1object = function (/* Uint8Array */raw_der)
{
    this.raw_der = raw_der;
    this.index = 0;
    this.tag = this.readDERByte ();
//    console.debug ("TAG=" + this.tag + " RDL=" + raw_der.length + " DA=" + org.webpki.util.ByteArray.toHex (raw_der));
    var length = this.readDERByte ();
    if ((length & 0x80) != 0)
    {
        var bytes = length & 0x7F;
        length = 0;
        while (bytes-- > 0)
        {
            length <<= 8;
            length += this.readDERByte ();
        }
    }
    this.body = new Uint8Array (raw_der.subarray (this.index, this.index + length));
    if (this.tag == org.webpki.asn1.TAGS.SEQUENCE)
    {
        this.components = [];
        var new_der = this.body;
        while (new_der.length != 0)
        {
            var asn1_object = new org.webpki.asn1.ParsedASN1object (new_der);
            var chunk = asn1_object.body.length + asn1_object.index; 
            this.components[this.components.length] = asn1_object;
            if (chunk > new_der.length)
            {
                org.webpki.asn1._error ("Length error for tag: " + asn1_object.tag);
            }
            new_der = new Uint8Array (new_der.subarray (chunk));
        }
    }
    return this;
};

/* int */org.webpki.asn1.ParsedASN1object.prototype.readDERByte = function ()
{
    if (this.index >= this.raw_der.length)
    {
        org.webpki.asn1._error ("Buffer overrun");
    }
    return this.raw_der[this.index++];
};

/* int */org.webpki.asn1.ParsedASN1object.prototype.numberOfComponents = function ()
{
    if (this.components === undefined)
    {
        org.webpki.asn1._error ("This object type doesn't have components: " + this.tag);
    }
    return this.components.length;
};

/* ParsedASN1object */org.webpki.asn1.ParsedASN1object.prototype.getComponent = function (index)
{
    if (index >= this.numberOfComponents ())
    {
        org.webpki.asn1._error ("Component index out of range: " + index);
    }
    return this.components[index];
};

/* Unit8Array */org.webpki.asn1.ParsedASN1object.prototype.getASN1ObjectIDRawData = function ()
{
    return this.getRawData (org.webpki.asn1.TAGS.OID);
};

/* Unit8Array */org.webpki.asn1.ParsedASN1object.prototype.getASN1Integer = function ()
{
    return this.getRawData (org.webpki.asn1.TAGS.INTEGER);
};

/* Unit8Array */org.webpki.asn1.ParsedASN1object.prototype.getASN1BitString = function (/* boolean */unused_must_be_zero)
{
    var raw = this.getRawData (org.webpki.asn1.TAGS.BITSTRING);
    if (unused_must_be_zero)
    {
        if (raw[0] != 0)
        {
            org.webpki.asn1._error ("Bitstring with unused bits not allowed");
        }
        raw = new Uint8Array (raw.subarray (1));
    }
    return raw;
};

/* void */org.webpki.asn1.ParsedASN1object.prototype.getASN1NULL = function ()
{
    if (this.getRawData (org.webpki.asn1.TAGS.NULL).length != 0)
    {
        org.webpki.asn1._error ("Misformed ASN.1 NULL");
    }
};

/* ParsedASN1object */org.webpki.asn1.ParsedASN1object.prototype.getASN1Sequence = function ()
{
    this.getRawData (org.webpki.asn1.TAGS.SEQUENCE);
    return this;
};

/* Unit8Array */org.webpki.asn1.ParsedASN1object.prototype.getRawData = function (/* int */tag)
{
    if (tag != this.tag)
    {
        org.webpki.asn1._error ("Tag mismatch, expected: " + tag + " got: " + this.tag);
    }
    return this.body;
};

/* ParsedASN1object */org.webpki.asn1.ParsedASN1Sequence = function (/* Uint8Array */raw_der)
{
    var sequence = new org.webpki.asn1.ParsedASN1object (raw_der, org.webpki.asn1.TAGS.SEQUENCE);
    if (sequence.body.length != (sequence.raw_der.length - sequence.index))
    {
        org.webpki.asn1._error ("Sequence length error");
    }
    return sequence;
};
