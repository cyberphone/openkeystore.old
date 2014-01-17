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

org.webpki.json.JSONTypes = 
{
    NULL:
    {
        "enumvalue" : 0,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.NULL; }
    },
    BOOLEAN:
    {
        "enumvalue" : 1,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.BOOLEAN; }
    },
    INTEGER:
    {
        "enumvalue" : 2,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.INTEGER; }
    },
    DECIMAL:
    {
        "enumvalue" : 3,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.DECIMAL || o == org.webpki.json.JSONTypes.INTEGER; }
    },
    DOUBLE:
    {
        "enumvalue" : 4,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.DOUBLE || o == org.webpki.json.JSONTypes.DECIMAL || o == org.webpki.json.JSONTypes.INTEGER; }
    },
    STRING:
    {
        "enumvalue" : 5,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.STRING; }
    },
    ARRAY:
    {
        "enumvalue" : 10,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.ARRAY; }
    },
    OBJECT:
    {
        "enumvalue" : 11,
        "isCompatible" : function (o) { return o == org.webpki.json.JSONTypes.OBJECT; }
    }
};

org.webpki.json.JSONTypes.getJSONTypeName = function (json_type)
{
    for (var obj in org.webpki.json.JSONTypes)
    {
        if (org.webpki.json.JSONTypes[obj].enumvalue == json_type.enumvalue)
        {
            return obj;
        }
    }
    return "UNKNOWN!";
};

