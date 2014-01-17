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
/*                       JSONDecoderCache                         */
/*================================================================*/

org.webpki.json.JSONDecoderCache = function ()
{
    this.cache = new Object ();
    this.check_for_unread = true;
};

org.webpki.json.JSONDecoderCache.CONTEXT_QUALIFIER_DIVIDER = '$';

org.webpki.json.JSONDecoderCache.CONTEXT_JSON              = "@context";
org.webpki.json.JSONDecoderCache.QUALIFIER_JSON            = "@qualifier";

org.webpki.json.JSONDecoderCache.prototype.addToCache = function (object_class)
{
    var object = new object_class ();
    if (object.getContext === undefined)
    {
        org.webpki.json.JSONError._error ('Missing mandatory method "getContext"');
    }
    if (object.readJSONData === undefined)
    {
        org.webpki.json.JSONError._error ('Missing mandatory method "readJSONData"');
    }
    var object_id = object.getContext ();
    if (object.getQualifier != undefined)
    {
        object_id += org.webpki.json.JSONDecoderCache.CONTEXT_QUALIFIER_DIVIDER + object.getQualifier ();
    }
    if (this.cache[object_id] != null)
    {
        org.webpki.json.JSONError._error ("Duplicate definition: " + object_id);
    }
    this.cache[object_id] = object_class;
};

org.webpki.json.JSONDecoderCache._checkForUnread = function (json_object)
{
    for (var i = 0; i < json_object.property_list.length; i++)
    {
        var name = json_object.property_list[i].name;
        var value = json_object.property_list[i].value;
        if (!json_object.read_flag[name])
        {
            org.webpki.json.JSONError._error ('Property "' + name + '" was never read');
        }
        if (value.type == org.webpki.json.JSONTypes.OBJECT)
        {
            org.webpki.json.JSONDecoderCache._checkForUnread (value.value);
        }
        else if (value.type == org.webpki.json.JSONTypes.ARRAY)
        {
            for (var q = 0; q < value.value.length; q++)
            {
                var object = value.value[q];
                if (object.type == org.webpki.json.JSONTypes.OBJECT)
                {
                    org.webpki.json.JSONDecoderCache._checkForUnread (object.value);
                }
            }
        }
    }
};

org.webpki.json.JSONDecoderCache.prototype.parse = function (raw_json_document)
{
    var json_object_reader = org.webpki.json.JSONParser.parse (raw_json_document);
    var object_id = json_object_reader.getString (org.webpki.json.JSONDecoderCache.CONTEXT_JSON);
    var qualifier = json_object_reader.getStringConditional (org.webpki.json.JSONDecoderCache.QUALIFIER_JSON);
    if (qualifier != null)
    {
        object_id += org.webpki.json.JSONDecoderCache.CONTEXT_QUALIFIER_DIVIDER + qualifier;
    }
    var object_class = this.cache[object_id];
    if (object_class == null)
    {
        org.webpki.json.JSONError._error ("No document matching: " + object_id);
    }
    var object = new object_class ();
    object.readJSONData (json_object_reader);
    object._root = json_object_reader.root;
    if (this.check_for_unread)
    {
        org.webpki.json.JSONDecoderCache._checkForUnread (object._root);
    }
    return object;
};

org.webpki.json.JSONDecoderCache.prototype.setCheckForUnreadProperties = function (/* boolean */flag)
{
    this.check_for_unread = flag;
};
