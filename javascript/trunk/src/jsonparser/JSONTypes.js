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
/*                            JSONTypes                           */
/*================================================================*/

var JSONTypes = 
{
    NULL:
    {
        "enumvalue" : 0,
        "isCompatible" : function (o) { return o == JSONTypes.NULL; }
    },
    BOOLEAN:
    {
        "enumvalue" : 1,
        "isCompatible" : function (o) { return o == JSONTypes.BOOLEAN; }
    },
    INTEGER:
    {
        "enumvalue" : 2,
        "isCompatible" : function (o) { return o == JSONTypes.INTEGER; }
    },
    DECIMAL:
    {
        "enumvalue" : 3,
        "isCompatible" : function (o) { return o == JSONTypes.DECIMAL || o == JSONTypes.INTEGER; }
    },
    DOUBLE:
    {
        "enumvalue" : 4,
        "isCompatible" : function (o) { return o == JSONTypes.DOUBLE || o == JSONTypes.DECIMAL || o == JSONTypes.INTEGER; }
    },
    STRING:
    {
        "enumvalue" : 5,
        "isCompatible" : function (o) { return o == JSONTypes.STRING; }
    },
    ARRAY:
    {
        "enumvalue" : 10,
        "isCompatible" : function (o) { return o == JSONTypes.ARRAY; }
    },
    OBJECT:
    {
        "enumvalue" : 11,
        "isCompatible" : function (o) { return o == JSONTypes.OBJECT; }
    }
};
