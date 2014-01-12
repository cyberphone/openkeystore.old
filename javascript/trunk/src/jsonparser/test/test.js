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
console.debug (org.webpki.json.JSONTypes.DOUBLE.isCompatible(org.webpki.json.JSONTypes.OBJECT));

loopa (org.webpki.json.JSONParser.parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
        0.00e4 , "bool": true, "arr":[5,7]}}').json);

loopa (org.webpki.json.JSONParser.parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
0.00e4 , "bool": true, "arr":[5,7]}}').getObject ("bello").json);

console.debug (org.webpki.json.JSONParser.parse ('[[{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
7 , "bool": false, "arr":[3]}}]]').getJSONArrayReader ().getArray ().getObject ().getObject ("bello").getArray ("arr").getInt ());

new org.webpki.json.JSONObjectWriter (new org.webpki.json.JSONObject ());
var newobjec = new org.webpki.json.JSONObjectWriter ();
newobjec.setInt ("kirt", 4).setObject ("Obja");
loopa (newobjec.root);
new org.webpki.json.JSONObjectWriter (org.webpki.json.JSONParser.parse ('{"hello": "wor\\n\\u0042\\u000Ald!"  , "bello"   : {   "kul":\
0.00e4 , "bool": true, "arr":[5,7]}}'));
var inbin = new Uint8Array ([0,2,99,46,34,97,57,78,9]);
var really_bigint = org.webpki.math.BigInteger.fromString ("20468687687668767676866876876876768768768768768767687687687687676709");
var a_long_one = org.webpki.math.BigInteger.fromString ("FF00000000000000", 16);
var double_trouble = 2.3e-25;
var big_dec = "3500000000000000000000000000.56";
var big_string = "abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghija";
newobjec = new org.webpki.json.JSONObjectWriter ();
var arr_writer = newobjec.setString ("dri", "dra")
        .setInt ("numbah", 6)
        .setBinary ("bin", inbin)
        .setBigInteger ("bigint", really_bigint)
        .setDouble ("double", double_trouble)
        .setLong ("long", a_long_one)
        .setBigDecimal ("bigdec", big_dec)
        
        .setArray ("arry").setString (big_string);
arr_writer.setBigInteger (really_bigint);
arr_writer.setInt (45);
arr_writer.setLong (a_long_one);
arr_writer.setDouble (double_trouble);
console.debug (newobjec.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT));
console.debug (newobjec.serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED));
var reader = org.webpki.json.JSONParser.parse (newobjec.serializeJSONObject (org.webpki.json.JSONOutputFormats.PRETTY_PRINT));
if (!reader.getBigInteger ("bigint").equals (really_bigint))
{
    throw "BigInit";
}
if (!reader.getLong ("long").equals (a_long_one))
{
    throw "Long";
}
if (reader.getDouble ("double") != double_trouble)
{
    throw "Double";
}
if (reader.getBigDecimal ("bigdec") != big_dec)
{
    throw "BigDec";
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
var arr_reader = reader.getArray ("arry");
if (!arr_reader.getString ().equals (big_string) ||
    !arr_reader.hasMore () ||
    !arr_reader.getBigInteger ().equals (really_bigint) ||
    arr_reader.getInt () != 45 ||
    !arr_reader.getLong ().equals (a_long_one) ||
    arr_reader.getDouble () != double_trouble ||
    arr_reader.hasMore ())
{
    throw "ARRAY";
}

var signature = org.webpki.json.JSONParser.parse (

'{\
"Now": "2013-12-23T23:25:10+01:00",\
"PaymentRequest": \
  {\
    "Currency": "USD",\
    "VAT": 1.45,\
    "Specification": \
      [{\
         "Units": 3,\
         "Description": "USB cable",\
         "SKU": "TR-46565666",\
         "UnitPrice": 4.50\
       },\
       {\
         "Units": 1,\
         "Description": "4G Router",\
         "SKU": "JK-56566655",\
         "UnitPrice": 39.99\
       }]\
  },\
"EscapeMe": "\\u000F\\u000aA\'\\u0042\\\\\\"\\/",\
"Signature": \
  {\
    "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",\
    "KeyInfo": \
      {\
        "PublicKey": \
          {\
            "EC": \
              {\
                "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",\
                "X": "lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk",\
                "Y": "LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA"\
              }\
          }\
      },\
    "SignatureValue": "MEUCIA1__ClTpOMBTCCA3oD3lzuaS3WACYR8qFDHpej5ZdEsAiEA3N5pWl2TOzzQfdtoc35S9n31mf-oP3_XBss8R8qjnvg"\
  }\
}'

);
console.debug (new org.webpki.json.JSONObjectWriter (signature).serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED));
