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
/*                       JSONSignatureTypes                       */
/*================================================================*/

org.webpki.json.JSONSignatureTypes = 
{
    X509_CERTIFICATE:
    {
        "toString": function () { return "X509 path";}
    },
    ASYMMETRIC_KEY:
    {
        "toString": function () { return "Asymmetric key";}
    },
    SYMMETRIC_KEY:
    {
        "toString": function () { return "Symmetric key";}
    }
};