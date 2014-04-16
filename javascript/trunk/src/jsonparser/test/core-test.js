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

var jo = new org.webpki.json.JSONObject ();
jo._setProperty("one", new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.INTEGER, 3));
jo._setProperty("two", new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.STRING, "hi"));
console.debug ("T=" + jo._getProperty ("two").type.enumvalue + " V="+ jo._getProperty ("two").value);
//jo._setProperty("two", new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.INTEGER, 3));
var jo1 = new org.webpki.json.JSONObject ();
jo1._setProperty("one1", new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.INTEGER, 4));
jo1._setProperty("two2", new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.OBJECT, jo));
jo1._setProperty("tree", new org.webpki.json.JSONValue (org.webpki.json.JSONTypes.STRING, "ghghg"));
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
        if (elem.value.type == org.webpki.json.JSONTypes.OBJECT)
        {
            console.debug (string);
            console.debug (space + '  {');
            indent += 4;
            loopa (elem.value.value);
            indent -= 4;
            console.debug (space + '  }');
        }
        else if (elem.value.type == org.webpki.json.JSONTypes.ARRAY)
        {
            console.debug (string + ' [' + elem.value.value.length + ']');
        }
        else
        {
            string += ' ';
            if (elem.value.type != org.webpki.json.JSONTypes.STRING)
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

loopa (org.webpki.json.JSONParser.parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
        0.00e4 , "bool": true, "arr":[5,7]}}').root);

loopa (org.webpki.json.JSONParser.parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
0.00e4 , "bool": true, "arr":[5,7]}}').getObject ("bello").root);

console.debug (org.webpki.json.JSONParser.parse ('[[{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
7 , "bool": false, "arr":[3]}}]]').getJSONArrayReader ().getArray ().getObject ().getObject ("bello").getArray ("arr").getInt ());

new org.webpki.json.JSONObjectWriter (new org.webpki.json.JSONObject ());
var newobjec = new org.webpki.json.JSONObjectWriter ();
newobjec.setInt ("kirt", 4).setObject ("Obja");
loopa (newobjec.root);
new org.webpki.json.JSONObjectWriter (org.webpki.json.JSONParser.parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
0.00e4 , "bool": true, "arr":[5,7]}}'));
var inbin = new Uint8Array ([0,2,99,46,34,97,57,78,9]);
var bin_arr = [];
bin_arr[0] = inbin;
bin_arr[1] = new Uint8Array ([255, 4, 8]);
var really_bigint = org.webpki.math.BigInteger.fromString ("20468687687668767676866876876876768768768768768767687687687687676709");
var a_long_one = org.webpki.math.BigInteger.fromString ("FF00000000000000", 16);
var double_trouble = 2.3e-25;
var big_dec = "3500000000000000000000000000.56";
var big_string = "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghija";
var now = new Date ();
newobjec = new org.webpki.json.JSONObjectWriter ();
var arr_writer = newobjec
        .setString ("dri", "dra")
        .setNULL ("not.much.there")
        .setStringArray ("strings!", ["a string", "another one"])
        .setBinaryArray ("binarr", bin_arr)
        .setInt ("numbah", 6)
        .setInt ("nobodycared", -5545)
        .setBinary ("bin", inbin)
        .setBigInteger ("bigint", really_bigint)
        .setDouble ("double", double_trouble)
        .setBoolean ("bool", true)
        .setBoolean ("bool2", false)
        .setLong ("long", a_long_one)
        .setBigDecimal ("bigdec", big_dec)
        .setDateTime ("now", now)
        
        .setArray ("arry").setString (big_string);
newobjec.setArray ("arr2").setArray ().setString ("The other one");
arr_writer
.setBigInteger (really_bigint)
.setInt (45)
.setLong (a_long_one)
.setNULL ()
.setInt (6)
.setBigDecimal (big_dec)
.setBoolean (true)
.setBoolean (false)
.setDateTime (now)
.setDouble (double_trouble);
console.debug (newobjec.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT));
var json1 = newobjec.serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED);
console.debug (json1);
var reader = org.webpki.json.JSONParser.parse (newobjec.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT));
reader.scanAway ("nobodycared");
if (!reader.getBigInteger ("bigint").equals (really_bigint))
{
    throw "BigInit";
}
if (!reader.getLong ("long").equals (a_long_one))
{
    throw "Long";
}
var strings = reader.getStringArray ("strings!");
if (strings.length != 2 || strings[1] != "another one")
{
    throw "String arr";
}
var blobs = reader.getBinaryArray ("binarr");
if (blobs.length != 2 || blobs[1].length != 3 || blobs[1][1] != 4)
{
    throw "Blob arr";
}
if (reader.getDouble ("double") != double_trouble)
{
    throw "Double";
}
if (reader.getBigDecimal ("bigdec") != big_dec)
{
    throw "BigDec";
}
if (!reader.getBoolean ("bool") || reader.getBoolean ("bool2"))
{
    throw "Bool";
}
if (reader.getDateTime ("now").getTime () != now.getTime ())
{
    throw "Date";
}
var bin = reader.getBinary ("bin");
if (bin.length != inbin.length)
{
    throw "Length";
}
for (var i = 0; i < bin.length; i++)
{
    if (bin[i] != inbin[i])
    {
    throw "Content";
    }
}
var props = "";
for (var i = 0; i < reader.getProperties ().length; i++)
{
    props += " " + reader.getProperties ()[i]; 
}
if (props != " dri not.much.there strings! binarr numbah nobodycared bin bigint double bool bool2 long bigdec now arry arr2")
{
    throw "Properties " + props;
}
if (reader.getStringConditional ("No") != null || reader.getStringConditional ("No", "Yes") != "Yes")
{
    throw "Conditional";
}
if (reader.getPropertyType ("No") != null || reader.getPropertyType ("numbah") != org.webpki.json.JSONTypes.INTEGER)
{
    throw "PropType";
}
if (reader.getArray ("arr2").getArray ().getString () != "The other one")
{
    throw "Arr+Arr";
}
var arr_reader = reader.getArray ("arry");
if (arr_reader.getString () != big_string ||
    !arr_reader.hasMore () ||
    !arr_reader.getBigInteger ().equals (really_bigint) ||
    arr_reader.getInt () != 45 ||
    !arr_reader.getLong ().equals (a_long_one) ||
    !arr_reader.getIfNULL () ||
    arr_reader.getIfNULL () ||
    arr_reader.getInt () != 6 ||
    arr_reader.getBigDecimal () != big_dec ||
    !arr_reader.getBoolean () ||
    arr_reader.getBoolean () ||
    arr_reader.getDateTime ().getTime () != now.getTime () ||
    arr_reader.getDouble () != double_trouble ||
    arr_reader.hasMore ())
{
    throw "ARRAY";
}

if (newobjec.createContainerObject ("Keeper").serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED)
        != ('{"Keeper":' + json1 + '}'))
{
    throw "Container";
}
try
{
    newobjec.setString ("dri", "blah");
    throw "Rewrite not ok";
}
catch (err)
{
}
newobjec.setupForRewrite ("dri");
newobjec.setString ("dri", "blih");

if (!org.webpki.util.ByteArray.equals (org.webpki.util.ByteArray.convertStringToUTF8 ("A\u20ac\u00c5"),
                                       new Uint8Array ([0x41, 0xE2, 0x82, 0xAC, 0xC3,0x85])))
{
    throw "UTF 8";
}

newobjec = new org.webpki.json.JSONObjectWriter ();
newobjec.setBigDecimal ("b1","5656656565656");
newobjec.setBigDecimal ("b2","565.6656565656");
try
{
    newobjec.setBigDecimal ("b3","565.6.656565656");
    throw "should bomb";
}
catch (err)
{
}
newobjec.setArray ("arr").setString ("gg").setBoolean (true);
newobjec.setArray ("arr2").setString ("gg").setString ("true");
reader = org.webpki.json.JSONParser.parse (newobjec.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT));
reader.getStringArray ("arr2");
try
{
    reader.getStringArray ("arr");
    throw "should bomb";
}
catch (err)
{
}

console.debug ("Successful");


