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
        complex : false
    },
    BOOLEAN:
    {
        complex : false
    },
    INTEGER:
    {
        complex : false
    },
    DOUBLE:
    {
        complex : false
    },
    STRING:
    {
        complex : false
    },
    ARRAY:
    {
        complex : true
    },
    OBJECT:
    {
        complex : true
    }
};

org.webpki.json.JSONTypes.getName = function (json_type)
{
    for (var obj in org.webpki.json.JSONTypes)
    {
        if (org.webpki.json.JSONTypes[obj]  == json_type)
        {
            return obj;
        }
    }
    return "UNKNOWN!";
};

org.webpki.json.JSONTypes._compatibilityTest = function (/* JSONTypes */expected_type, /* JSONValue */value)
{
    if (expected_type != value.type && 
        (expected_type != org.webpki.json.JSONTypes.DOUBLE || value.type != org.webpki.json.JSONTypes.INTEGER))
    {
        org.webpki.util._error ("Incompatible types, expected: " + 
                                org.webpki.json.JSONTypes.getName (expected_type) + 
                                " actual: " + org.webpki.json.JSONTypes.getName (value.type));
    }
};

