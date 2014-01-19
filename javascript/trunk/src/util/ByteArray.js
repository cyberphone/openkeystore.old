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
/*                            ByteArray                           */
/*================================================================*/

//* Encodes/decodes base64URL data as described in RFC 4648 Table 2.

org.webpki.util.ByteArray = {};

/* boolean */org.webpki.util.ByteArray.equals = function (/* Uint8Array */arg1, /* Uint8Array */arg2)
{
    if (arg1.length != arg2.length)
    {
        return false;
    }
    for (var i = 0; i < arg1.length; i++)
    {
        if (arg1[i] != arg2[i])
        {
            return false;
        }
    }
    return true;
};

/* Uint8Array */org.webpki.util.ByteArray.add = function (/* Uint8Array */arg1, /* Uint8Array */arg2)
{
    var combined = new Uint8Array (arg1.length + arg2.length);
    var i = 0;
    while (i < arg1.length)
    {
        combined[i] = arg1[i++];
    }
    for (var j = 0; j < arg2.length; j++)
    {
        combined[i++] = arg2[j];
    }
    return combined;
};

/* String */ org.webpki.util.ByteArray._hex = function (/* byte */i)
{
    if (i < 10)
    {
        return String.fromCharCode (i + 48);
    }
    return String.fromCharCode (i + 55);
};

/* String */org.webpki.util.ByteArray._twohex = function (/* byte */i)
{
    return org.webpki.util.ByteArray._hex (i / 16) + org.webpki.util.ByteArray._hex (i % 16);
};

/* String */org.webpki.util.ByteArray.toHex = function (/* Uint8Array */arg)
{
    var result = "";
    for (var i = 0; i < arg.length; i++)
    {
        result += " " + org.webpki.util.ByteArray._twohex (arg[i]);
    }
    return result;
};
