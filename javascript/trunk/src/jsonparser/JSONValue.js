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
/*                            webpki.org.json.JSONValue                           */
/*================================================================*/

/*================================================================*/
/*                            JSONValue                           */
/*================================================================*/

 webpki.org.json.JSONValue = function (type, value)
{
    this.type = type;
    this.value = value;
};

webpki.org.json.JSONValue.prototype.getJSONTypeName = function (json_type)
{
    for (var obj in webpki.org.json.JSONTypes)
    {
        if (webpki.org.json.JSONTypes[obj].enumvalue == json_type.enumvalue)
        {
            return obj;
        }
    }
    return "UNKNOWN!";
};
