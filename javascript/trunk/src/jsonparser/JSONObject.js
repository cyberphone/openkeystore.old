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
/*                           JSONObject                           */
/*================================================================*/

org.webpki.json.JSONObject = function ()
{
    this.property_list = [];
    this.read_flag = new Object ();
};

/* void */org.webpki.json.JSONObject.prototype._addProperty = function (/* String */name, /* org.webpki.json.JSONValue */value)
{
    if (!(value instanceof org.webpki.json.JSONValue))
    {
        org.webpki.json.JSONError._error ("Wrong value type: " + value);
    }
    var length = this.property_list.length;
    var new_property = new Object;
    new_property.name = name;
    new_property.value = value;
    for (var i = 0; i < length; i++)
    {
        if (this.property_list[i].name == name)
        {
            org.webpki.json.JSONError._error ("Property already defined: " + name);
        }
    }
    this.property_list[length] = new_property;
    this.read_flag.name = null;
};

org.webpki.json.JSONError._error = function (message)
{
    throw "JSONException: " + message;
};

org.webpki.json.JSONObject.prototype._getProperty = function (name)
{
    var length = this.property_list.length;
    for (var i = 0; i < length; i++)
    {
        if (this.property_list[i].name == name)
        {
            return this.property_list[i].value;
        }
    }
    return null;
};

org.webpki.json.JSONObject.prototype._isArray = function ()
{
    return this.property_list.length == 1 && !this.property_list[0].name;
};

org.webpki.json.JSONObject.prototype._setArray = function (/* org.webpki.json.JSONValue */array)
{
    this.property_list = [];
    var unnamed_property = new Object;
    unnamed_property.name = null;
    unnamed_property.value = array;
    this.property_list[0] = unnamed_property;
};
