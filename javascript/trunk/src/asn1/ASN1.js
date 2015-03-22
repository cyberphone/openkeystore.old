/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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

//* Ultra-light ASN.1 library in JavaScript

org.webpki.asn1.TAGS =
{
    OID                : 0x06,
    SEQUENCE           : 0x30,
    SET                : 0x31,
    INTEGER            : 0x02,
    NULL               : 0x05,
    BITSTRING          : 0x03,
    UTF8STRING         : 0x0C,
    BMPSTRING          : 0x1E,
    EXPLICIT_CONTEXT_0 : 0xA0,
    EXPLICIT_CONTEXT_1 : 0xA1,
    EXPLICIT_CONTEXT_3 : 0xA3,
    OCTET_STRING       : 0x04
};

org.webpki.asn1.LIBRARY_LIMIT = 50000;  // 50k of ASN.1 is all we care of

/* void */org.webpki.asn1._lengthCheck = function (/* int */length)
{
    if (length > org.webpki.asn1.LIBRARY_LIMIT)
    {
        org.webpki.util._error ("Exceeded library limit " + org.webpki.asn1.LIBRARY_LIMIT + " bytes");
    }
};

org.webpki.asn1.ASN1Encoder = function (/* byte */tag, /* ASN1Encoder or Uint8Array */argument)
{
    this.components = [];  /* ASN1Encoder or Uint8Array */
    this.components.push (argument);
    this.tag = tag;
    return this;
};

/* ASN1Encoder */org.webpki.asn1.ASN1Encoder.prototype.addComponent = function (/* ASN1Encoder */component)
{
    this.components.push (component);
    return this;
};

/* Uint8Array */org.webpki.asn1.ASN1Encoder.prototype.encode = function ()
{
    this.encoded = new Uint8Array ();
    for (var i = 0; i < this.components.length; i++)
    {
        if (this.components[i] instanceof org.webpki.asn1.ASN1Encoder)
        {
            this._update (this.components[i].encode ()); 
        }
        else
        {
            this._update (this.components[i]);
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
            this._update ([length >> 8]);
        }
        else
        {
            this.encoded[1] = 0x81;
        }
        this._update ([length & 0xFF]);
    }
    return this._update (body);
};

/* Uint8Array */org.webpki.asn1.ASN1Encoder.prototype._update = function (array)
{
    return this.encoded = org.webpki.util.ByteArray.add (this.encoded, array);
};

/* ASN1Decoder */org.webpki.asn1.ASN1Decoder = function (/* Uint8Array */raw_der)
{
    org.webpki.asn1._lengthCheck (raw_der.length);
    this.raw_der = raw_der;
    this.position = 0;
    this.tag = this._readDERByte ();
//    console.debug ("TAG=" + this.tag + " RDL=" + raw_der.length + " DA=" + org.webpki.util.ByteArray.toHex (raw_der));
    var length = this._readDERByte ();
    if ((length & 0x80) != 0)
    {
        var bytes = length & 0x7F;
        length = 0;
        while (bytes-- > 0)
        {
            length <<= 8;
            length += this._readDERByte ();
            org.webpki.asn1._lengthCheck (length);
        }
    }
    this.start_of_body = this.position;
    this.body = new Uint8Array (length);
    for (var i = 0; i < length; i++)
    {
        this.body[i] = this._readDERByte (); 
    }
    if (this.tag == org.webpki.asn1.TAGS.SEQUENCE || this.tag == org.webpki.asn1.TAGS.SET)
    {
        this.components = [];
        var new_der = this.body;
        while (new_der.length != 0)
        {
            var asn1_object = new org.webpki.asn1.ASN1Decoder (new_der);
            var chunk = asn1_object.body.length + asn1_object.start_of_body; 
            this.components.push (asn1_object);
            if (chunk > new_der.length)
            {
                org.webpki.util._error ("Length error for tag: " + asn1_object.tag);
            }
            new_der = new Uint8Array (new_der.subarray (chunk));
        }
    }
    else if (length == 0 && this.tag != org.webpki.asn1.TAGS.NULL)
    {
        org.webpki.util._error ("Zero-length body not permitted for tag: " + this.tag);
    }
    return this;
};

/* int */org.webpki.asn1.ASN1Decoder.prototype._readDERByte = function ()
{
    if (this.position >= this.raw_der.length)
    {
        org.webpki.util._error ("Buffer underrun for tag: " + this.tag);
    }
    return this.raw_der[this.position++];
};

/* int */org.webpki.asn1.ASN1Decoder.prototype.numberOfComponents = function ()
{
    if (this.components === undefined)
    {
        org.webpki.util._error ("This object type doesn't have components: " + this.tag);
    }
    return this.components.length;
};

/* ASN1Decoder */org.webpki.asn1.ASN1Decoder.prototype.getComponent = function (index)
{
    if (index >= this.numberOfComponents ())
    {
        org.webpki.util._error ("Component index out of range: " + index);
    }
    return this.components[index];
};

/* Uint8Array */org.webpki.asn1.ASN1Decoder.prototype.getASN1ObjectIDRawData = function ()
{
    return this._getBodyData (org.webpki.asn1.TAGS.OID);
};

/* Uint8Array */org.webpki.asn1.ASN1Decoder.prototype.getASN1Integer = function ()
{
    return this._getBodyData (org.webpki.asn1.TAGS.INTEGER);
};

/* Uint8Array */org.webpki.asn1.ASN1Decoder.prototype.getASN1PositiveInteger = function ()
{
    var data = this.getASN1Integer ();
    if (data[0] > 127)
    {
        org.webpki.util._error ("Unexpected negative integer value");
    }
    return data;
};

/* Uint8Array */org.webpki.asn1.ASN1Decoder.prototype.getASN1BitString = function (/* boolean */unused_must_be_zero)
{
    var raw = this._getBodyData (org.webpki.asn1.TAGS.BITSTRING);
    if (unused_must_be_zero)
    {
        if (raw[0] != 0)
        {
            org.webpki.util._error ("Bitstring with unused bits not allowed");
        }
        raw = new Uint8Array (raw.subarray (1));
    }
    return raw;
};

/* void */org.webpki.asn1.ASN1Decoder.prototype.getASN1NULL = function ()
{
    if (this._getBodyData (org.webpki.asn1.TAGS.NULL).length != 0)
    {
        org.webpki.util._error ("Misformed ASN.1 NULL");
    }
};

/* ASN1Decoder */org.webpki.asn1.ASN1Decoder.prototype.getASN1Sequence = function ()
{
    this._getBodyData (org.webpki.asn1.TAGS.SEQUENCE);
    return this;
};

/* ASN1Decoder */org.webpki.asn1.ASN1Decoder.prototype.getASN1Set = function ()
{
    this._getBodyData (org.webpki.asn1.TAGS.SET);
    return this;
};

/* Uint8Array */org.webpki.asn1.ASN1Decoder.prototype._getBodyData = function (/* int */tag)
{
    if (tag != this.tag)
    {
        org.webpki.util._error ("Tag mismatch, expected: " + tag + " got: " + this.tag);
    }
    return this.body;
};

/* Uint8Array */org.webpki.asn1.ASN1Decoder.prototype.getBodyData = function ()
{
    return this._getBodyData (this.tag);
};

/* int */org.webpki.asn1.ASN1Decoder.prototype.getTag = function ()
{
    return this.tag;
};

/* Uint8Array */org.webpki.asn1.ASN1Decoder.prototype.encode = function ()
{
    return new Uint8Array (this.raw_der.subarray (0, this.body.length + this.start_of_body));
};

/* ASN1Decoder */org.webpki.asn1.ASN1SequenceDecoder = function (/* Uint8Array */raw_der)
{
    var sequence = new org.webpki.asn1.ASN1Decoder (raw_der, org.webpki.asn1.TAGS.SEQUENCE);
    if (sequence.body.length != (raw_der.length - sequence.start_of_body))
    {
        org.webpki.util._error ("Sequence length error");
    }
    return sequence;
};
