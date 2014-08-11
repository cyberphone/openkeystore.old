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

/*void */org.webpki.json.JSONObject._checkForUnread = function (json_object)
{
    for (var i = 0; i < json_object.property_list.length; i++)
    {
        var name = json_object.property_list[i].name;
        var value = json_object.property_list[i].value;
        if (!json_object.read_flag[name])
        {
            org.webpki.util._error ('Property "' + name + '" was never read');
        }
        if (value.type == org.webpki.json.JSONTypes.OBJECT)
        {
            org.webpki.json.JSONObject._checkForUnread (value.value);
        }
        else if (value.type == org.webpki.json.JSONTypes.ARRAY)
        {
            for (var q = 0; q < value.value.length; q++)
            {
                var object = value.value[q];
                if (object.type == org.webpki.json.JSONTypes.OBJECT)
                {
                    org.webpki.json.JSONObject._checkForUnread (object.value);
                }
            }
        }
    }
};

/* void */org.webpki.json.JSONObject.prototype._setProperty = function (/* String */name, /* JSONValue */value)
{
    if (!(value instanceof org.webpki.json.JSONValue))
    {
        org.webpki.util._error ("Wrong value type: " + value);
    }
    var length = this.property_list.length;
    var new_property = new Object;
    new_property.name = name;
    new_property.value = value;
    for (var i = 0; i < length; i++)
    {
        if (this.property_list[i].name == name)
        {
            // For setupForRewrite
            if (this.property_list[i].value == null)
            {
                length = i;
                break;
            }
            org.webpki.util._error ("Property already defined: " + name);
        }
    }
    this.property_list[length] = new_property;
    this.read_flag[name] = null;
};

/* JSONValue */org.webpki.json.JSONObject.prototype._getProperty = function (name)
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

/* boolean */org.webpki.json.JSONObject.prototype._isArray = function ()
{
    return this.property_list.length == 1 && !this.property_list[0].name;
};

/* void */org.webpki.json.JSONObject.prototype._setArray = function (/* JSONValue */array)
{
    this.property_list = [];
    var unnamed_property = new Object;
    unnamed_property.name = null;
    unnamed_property.value = array;
    this.property_list[0] = unnamed_property;
};
