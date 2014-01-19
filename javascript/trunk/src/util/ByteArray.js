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
