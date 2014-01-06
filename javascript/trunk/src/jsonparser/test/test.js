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

var jo = new JSONObject ();
jo._addProperty("one", new JSONValue (JSONTypes.INTEGER, 3));
jo._addProperty("two", new JSONValue (JSONTypes.STRING, "hi"));
console.debug ("T=" + jo._getProperty ("two").type.enumvalue + " V="+ jo._getProperty ("two").value)
//jo._addProperty("two", new JSONValue (JSONTypes.INTEGER, 3));
var jo1 = new JSONObject ();
jo1._addProperty("one1", new JSONValue (JSONTypes.INTEGER, 4));
jo1._addProperty("two2", new JSONValue (JSONTypes.OBJECT, jo));
jo1._addProperty("tree", new JSONValue (JSONTypes.STRING, "ghghg"));
console.debug ("l1=" + jo1.property_list.length);
console.debug ("l=" + jo.property_list.length);

var indent = 0;
function loopa (o)
{
    var space = "";
    for (var i = 0; i < indent; i++)
    {
        space += ' ';
    }
    for (var i = 0; i < o.property_list.length; i++)
    {
        var elem = o.property_list[i];
        var string = space + '"' + elem.name + '":';
        if (elem.value.type == JSONTypes.OBJECT)
        {
            console.debug (string);
            console.debug (space + '  {');
            indent += 4;
            loopa (elem.value.value);
            indent -= 4;
            console.debug (space + '  }');
        }
        else if (elem.value.type == JSONTypes.ARRAY)
        {
            console.debug (string + ' [' + elem.value.value.length + ']');
        }
        else
        {
            string += ' ';
            if (elem.value.type != JSONTypes.STRING)
            {
                string += elem.value.value; 
            }
            else
            {
                string += '"' + elem.value.value + '"'; 
            }
            console.debug (string);
        }
    }
}

loopa (jo1);
console.debug (JSONTypes.DOUBLE.isCompatible(JSONTypes.OBJECT));

loopa (new JSONParser ().parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
        0.00e4 , "bool": true, "arr":[5,7]}}').json);

loopa (new JSONParser ().parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
0.00e4 , "bool": true, "arr":[5,7]}}').getObject ("bello").json);

console.debug (new JSONParser ().parse ('[[{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
7 , "bool": false, "arr":[3]}}]]').getJSONArrayReader ().getArray ().getObject ().getObject ("bello").getArray ("arr").getInt ());

new JSONObjectWriter (new JSONObject ());
var newobjec = new JSONObjectWriter ();
newobjec.setInt ("kirt", 4).setObject ("Obja");
loopa (newobjec.root);
new JSONObjectWriter (new JSONParser ().parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
0.00e4 , "bool": true, "arr":[5,7]}}'));

newobjec = new JSONObjectWriter ();
newobjec.setString ("dri", "dra").setInt ("numbah", 6).setArray ("arry").setString ("abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghija");
console.debug (newobjec.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT));
console.debug (newobjec.serializeJSONObject (JSONOutputFormats.CANONICALIZED));

