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

/* void */org.webpki.json.JSONDecoderCache.prototype.addToCache = function (/* decoder */object_class)
{
    var object = new object_class ();
    if (object.getContext === undefined)
    {
        org.webpki.util._error ('Missing mandatory method "getContext"');
    }
    if (object.readJSONData === undefined)
    {
        org.webpki.util._error ('Missing mandatory method "readJSONData"');
    }
    var object_id = object.getContext ();
    if (object.getQualifier != undefined)
    {
        object_id += org.webpki.json.JSONDecoderCache.CONTEXT_QUALIFIER_DIVIDER + object.getQualifier ();
    }
    if (this.cache[object_id] != null)
    {
        org.webpki.util._error ("Duplicate definition: " + object_id);
    }
    this.cache[object_id] = object_class;
};

/* deserialized JSON object */org.webpki.json.JSONDecoderCache.prototype.parse = function (raw_json_document)
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
        org.webpki.util._error ("No document matching: " + object_id);
    }
    var object = new object_class ();
    object.readJSONData (json_object_reader);
    object._root = json_object_reader.root;
    if (this.check_for_unread)
    {
        org.webpki.json.JSONObject._checkObjectForUnread (object._root);
    }
    return object;
};

/* void */org.webpki.json.JSONDecoderCache.prototype.setCheckForUnreadProperties = function (/* boolean */flag)
{
    this.check_for_unread = flag;
};
