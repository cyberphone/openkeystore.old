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
/*                            Base64URL                           */
/*================================================================*/

//* Encodes/decodes base64URL data as described in RFC 4648 Table 2.

org.webpki.util.Base64URL =
{
    BASE64URL :
    [//  0   1   2   3   4   5   6   7
        'A','B','C','D','E','F','G','H', // 0
        'I','J','K','L','M','N','O','P', // 1
        'Q','R','S','T','U','V','W','X', // 2
        'Y','Z','a','b','c','d','e','f', // 3
        'g','h','i','j','k','l','m','n', // 4
        'o','p','q','r','s','t','u','v', // 5
        'w','x','y','z','0','1','2','3', // 6
        '4','5','6','7','8','9','-','_'  // 7
    ],
    DECODE_TABLE :
    [
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, 62, -1, -1,
        52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6, 
         7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, 63,
        -1, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51
    ]
};

      ////////////////////
     ////   DECODE   //// Throws Base64Exception if argument isn't base64URL
    ////////////////////

/* Uint8Array */org.webpki.util.Base64URL.decode = function (/* String */ encoded)
{
    var semidecoded = new Uint8Array (encoded.length);
    for (var i = 0; i < encoded.length; i++)
    {
        var c = encoded.charCodeAt (i);
        if (c >= org.webpki.util.Base64URL.DECODE_TABLE.length || (c = org.webpki.util.Base64URL.DECODE_TABLE[c]) < 0)
        {
            org.webpki.util._error ("Bad character at index " + i);
        }
        semidecoded[i] = c;
    }
    
    var encoded_length_modulo_4 = Math.floor (encoded.length % 4);
    var decoded_length = Math.floor (encoded.length / 4) * 3;
    if (encoded_length_modulo_4 != 0)
    {
        decoded_length += encoded_length_modulo_4 - 1;
    }
    var decoded = new Uint8Array (decoded_length);
    var decoded_length_modulo_3 = Math.floor (decoded_length % 3);
    if (decoded_length_modulo_3 == 0 && encoded_length_modulo_4 != 0)
    {
        org.webpki.util._error ("Wrong number of characters");
    }

    // -----:  D E C O D E :-----
    var i = 0, j = 0;
    //decode in groups of four bytes
    while (j < decoded.length - decoded_length_modulo_3)
    {
        decoded[j++] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);
        decoded[j++] = (semidecoded[i++] << 4) | (semidecoded[i] >>> 2);
        decoded[j++] = (semidecoded[i++] << 6) | semidecoded[i++];
    }
    //decode "odd" bytes
    if (decoded_length_modulo_3 == 1)
    {
        decoded[j] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);
        if (semidecoded[i] & 0x0F)
        {
            org.webpki.util._error ("Wrong termination character");
        }
    }
    else if (decoded_length_modulo_3 == 2)
    {
        decoded[j++] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);
        decoded[j] = (semidecoded[i++] << 4) | (semidecoded[i] >>> 2);
        if (semidecoded[i] & 0x03)
        {
            org.webpki.util._error ("Wrong termination character");
        }
    }
    return decoded;
};
  
      ////////////////////
     ////   ENCODE   //// Does not throw exceptions
    ////////////////////

/* String */org.webpki.util.Base64URL.encode = function (/* Uint8Array */uncoded)
{
    var encoded = new String ();
    var i = 0;
    var modulo3 = uncoded.length % 3;
    while (i < uncoded.length - modulo3)
    {
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] >>> 2) & 0x3F];
        encoded += org.webpki.util.Base64URL.BASE64URL[((uncoded[i++] << 4) & 0x30) | ((uncoded[i] >>> 4) & 0x0F)];
        encoded += org.webpki.util.Base64URL.BASE64URL[((uncoded[i++] << 2) & 0x3C) | ((uncoded[i] >>> 6) & 0x03)];
        encoded += org.webpki.util.Base64URL.BASE64URL[uncoded[i++] & 0x3F];
    }
    if (modulo3 == 1)
    {
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] >>> 2) & 0x3F];
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] << 4) & 0x30];
    }
    else if (modulo3 == 2)
    {
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] >>> 2) & 0x3F];
        encoded += org.webpki.util.Base64URL.BASE64URL[((uncoded[i++] << 4) & 0x30) | ((uncoded[i] >>> 4) & 0x0F)];
        encoded += org.webpki.util.Base64URL.BASE64URL[(uncoded[i] << 2) & 0x3C];
    }
    return encoded;
};
