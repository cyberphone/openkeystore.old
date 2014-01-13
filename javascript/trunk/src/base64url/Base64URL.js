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
        switch (encoded.charAt (i))
        {
            case 'A': semidecoded[i] = 0; break;
            case 'B': semidecoded[i] = 1; break;
            case 'C': semidecoded[i] = 2; break;
            case 'D': semidecoded[i] = 3; break;
            case 'E': semidecoded[i] = 4; break;
            case 'F': semidecoded[i] = 5; break;
            case 'G': semidecoded[i] = 6; break;
            case 'H': semidecoded[i] = 7; break;
            case 'I': semidecoded[i] = 8; break;
            case 'J': semidecoded[i] = 9; break;
            case 'K': semidecoded[i] = 10; break;
            case 'L': semidecoded[i] = 11; break;
            case 'M': semidecoded[i] = 12; break;
            case 'N': semidecoded[i] = 13; break;
            case 'O': semidecoded[i] = 14; break;
            case 'P': semidecoded[i] = 15; break;
            case 'Q': semidecoded[i] = 16; break;
            case 'R': semidecoded[i] = 17; break;
            case 'S': semidecoded[i] = 18; break;
            case 'T': semidecoded[i] = 19; break;
            case 'U': semidecoded[i] = 20; break;
            case 'V': semidecoded[i] = 21; break;
            case 'W': semidecoded[i] = 22; break;
            case 'X': semidecoded[i] = 23; break;
            case 'Y': semidecoded[i] = 24; break;
            case 'Z': semidecoded[i] = 25; break;
            case 'a': semidecoded[i] = 26; break;
            case 'b': semidecoded[i] = 27; break;
            case 'c': semidecoded[i] = 28; break;
            case 'd': semidecoded[i] = 29; break;
            case 'e': semidecoded[i] = 30; break;
            case 'f': semidecoded[i] = 31; break;
            case 'g': semidecoded[i] = 32; break;
            case 'h': semidecoded[i] = 33; break;
            case 'i': semidecoded[i] = 34; break;
            case 'j': semidecoded[i] = 35; break;
            case 'k': semidecoded[i] = 36; break;
            case 'l': semidecoded[i] = 37; break;
            case 'm': semidecoded[i] = 38; break;
            case 'n': semidecoded[i] = 39; break;
            case 'o': semidecoded[i] = 40; break;
            case 'p': semidecoded[i] = 41; break;
            case 'q': semidecoded[i] = 42; break;
            case 'r': semidecoded[i] = 43; break;
            case 's': semidecoded[i] = 44; break;
            case 't': semidecoded[i] = 45; break;
            case 'u': semidecoded[i] = 46; break;
            case 'v': semidecoded[i] = 47; break;
            case 'w': semidecoded[i] = 48; break;
            case 'x': semidecoded[i] = 49; break;
            case 'y': semidecoded[i] = 50; break;
            case 'z': semidecoded[i] = 51; break;
            case '0': semidecoded[i] = 52; break;
            case '1': semidecoded[i] = 53; break;
            case '2': semidecoded[i] = 54; break;
            case '3': semidecoded[i] = 55; break;
            case '4': semidecoded[i] = 56; break;
            case '5': semidecoded[i] = 57; break;
            case '6': semidecoded[i] = 58; break;
            case '7': semidecoded[i] = 59; break;
            case '8': semidecoded[i] = 60; break;
            case '9': semidecoded[i] = 61; break;
            case '-': semidecoded[i] = 62; break;
            case '_': semidecoded[i] = 63; break;
            default: throw "Base64Exception: bad charcter at index " + i;
        }
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
        throw "Base64Exception: wrong number of characters";
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
            throw "Base64Exception: wrong termination character";
        }
    }
    else if (decoded_length_modulo_3 == 2)
    {
        decoded[j++] = (semidecoded[i++] << 2) | (semidecoded[i] >>> 4);
        decoded[j] = (semidecoded[i++] << 4) | (semidecoded[i] >>> 2);
        if (semidecoded[i] & 0x03)
        {
            throw "Base64Exception: wrong termination character";
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
