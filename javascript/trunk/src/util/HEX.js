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
/*                              HEX                               */
/*================================================================*/

//* Just to avoid duplication all over the place

org.webpki.util.HEX = {};

/* String */ org.webpki.util.HEX.oneHex = function (/* byte */value)
{
    if (value < 10)
    {
        return String.fromCharCode (value + 48);
    }
    return String.fromCharCode (value + 87);
};

/* String */org.webpki.util.HEX.twoHex = function (/* byte */value)
{
    return org.webpki.util.HEX.oneHex (value >>> 4) + org.webpki.util.HEX.oneHex (value & 0xF);
};

/* String */ org.webpki.util.HEX.fourHex = function (/* int */value)
{
    return org.webpki.util.HEX.twoHex (value >>> 8) + org.webpki.util.HEX.twoHex (value & 0xFF);
};
