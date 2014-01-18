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
console.debug ("HI=" + reader.getDateTime ("now").toString () + "/" + now.toString ());
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

var brainpool = 
'{\
  "PublicKey":\
    {\
      "EC":\
        {\
          "NamedCurve": "http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1",\
            "X": "Qxs3Hv-PApEUCw-FB0dWkHQH95D2XAXaf0n1csqsGs0",\
            "Y": "NT-h7rF7-hMbwqN2j1o88v1JajJJ4OhS_-pUhoz56lI"\
        }\
    }\
}';

var rsa_pk =
'{\
  "PublicKey":\
    {\
      "RSA":\
        {\
          "Modulus": "mTCYGokBP5ZlDB5dqi-t588buGgo_I3vZun3aBuM8t65b8Vo2_Rsqr57L3MJQ8cHM7\
GNYFAI1NRPSozjSH563wvmN7wbSC1EcxyQc79tviBzF77A0J3nSnROVFkZWi88NUwZGgoLzDhd-f-pdFoma46bhhFB\
SQNchWaOpHL6tep-BJp1vjN033yi42wJ-RDvnEonRrp-n-ji706A33UA9aUmpIGVBBW6tirR-HrKFeusgpqWPLaPM_\
hq0iZYO3kJNYe2uxHRuOs7DrOMTWjgnYUBCWZsDw3MY4mko5eXOdAy1cEvfdOBpJh85DL64If34FBibzu-PQ4ZK5INrxYq2w",\
          "Exponent": "AQAB"\
        }\
    }\
}';

var x509certpath = 
'{\
"X509CertificatePath":\
  [\
    "MIIDYzCCAkugAwIBAgIGAUNB6_yYMA0GCSqGSIb3DQEBCwUAMEMxEzARBgoJkiaJk_IsZAEZFgNvcmcx\
FjAUBgoJkiaJk_IsZAEZFgZ3ZWJwa2kxFDASBgNVBAMTC0RlbW8gU3ViIENBMB4XDTEzMTIzMDA1MTM0MVoXDTM4M\
TIzMDA1MTM0MVowQzEjMCEGCSqGSIb3DQEJARYUam9obi5kb2VAZXhhbXBsZS5jb20xHDAaBgNVBAMTE0tleUdlbj\
IgVHJ1c3RBbmNob3IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm6sjhAcaAS4VFYqrjo41yXk7tkWx\
c_d1ELdmnS7NWEJiOL8pKmf3nBZjiik240jrLLoVJwJyZg5opicRPXHkxJEerpkPw031soR4lkeaJG5eWDz1Aa1fU\
5S6qZA2G032T9RYun7uZ9uzeYXCkrVX3rE82JqU_W2k0h6M_JEWxmL-ACzOBxq4J7wXwfzYJ7qUkLBc1xrwMElrFJ\
9iYLdxEtdzyTCUBtJ3R1jVsFmBx_eS4c2z3Y6CbPj6dWbwbkHmn8Kw32NBqXk0YpyBmH76mdpeADmPRyVjcTsvubb\
24BgW932y_jMwrQ7iNKZLUtNqQ0ZGQqcdwpWpak1IhWRgRAgMBAAGjXTBbMAkGA1UdEwQCMAAwDgYDVR0PAQH_BAQ\
DAgOIMB0GA1UdDgQWBBTYR6ECqJXkUBS75b5whr1SonP5zTAfBgNVHSMEGDAWgBRZXCF2vVvvaakHecbUVh7jS1yI\
VTANBgkqhkiG9w0BAQsFAAOCAQEAdv_TGGJ-v5AZ6Scxhr7Z6kd-Rm2tLqstCdrhCGvvr3DYfU82ei4r3DHvlRyht\
ihM1KPwG1Hkeldlb3sfX__Wxowo7hLXsVHV9LMNRmzouPiwB6S0eDJKr8-vQNuXCozSQPjc1mjTGqCOhIf9kqWO3j\
gELCUN6G5nYEDWs4TUu4mbdHrlBwlHtkUR13POlzt_gaWnevWzmHb164uD0KBY5vcxCYIDg87lqpG4XLZLu0UEq_W\
zLpX6rwYJQVFqXryEQsRQfFHWdjMAPcSDojfXtGpa5ivmYomY4IugxZa_FIF7EQOGNgpSMDRAvPY6U1xn7FLiCK_XmSjDpf2utKfkpQ",\
        "MIIDZjCCAk6gAwIBAgICAMgwDQYJKoZIhvcNAQELBQAwRDETMBEGCgmSJomT8ixkARkWA29yZzEWMBQG\
CgmSJomT8ixkARkWBndlYnBraTEVMBMGA1UEAxMMRGVtbyBSb290IENBMB4XDTA1MDcxMDEwMDAwMFoXDTI1MDcxM\
DA5NTk1OVowQzETMBEGCgmSJomT8ixkARkWA29yZzEWMBQGCgmSJomT8ixkARkWBndlYnBraTEUMBIGA1UEAxMLRG\
VtbyBTdWIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQI1w6lq0AsHbWMes8i_UGBeVQnlbzL2N\
8VyLjkbT3HXNHPUTjWWQElhoRzFA2xPaH--V_ecgr2Dkievrm-B5yIsdAL4oWWmgZ9KVMSfOrl5jy843p6AA55CHl\
P4j8v1uU1SpexIMUegDcNPlBwSRc0PPX-uqQ1STRg0kUgi4Bap7U5IRxTvp06adFXU4Bjr85ML7VZ3j-164t6mLnw\
F5RChJMlO7aVuz6TwxnWqeZytjFOei742dgbX9SHPVvytLtbFp4V_VFoEhaOXLZiOudPvpVwVdlfgE0AtiGHEWrfA\
74BU5XhME6UXzjcl3y3Ic304YGymo2jvmOwBki5wb3AgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH\
_BAQDAgEGMB0GA1UdDgQWBBRZXCF2vVvvaakHecbUVh7jS1yIVTAfBgNVHSMEGDAWgBRaQnES9aDCSV_XOklJczxn\
qxI4_DANBgkqhkiG9w0BAQsFAAOCAQEAMlPdBaZ_-AMDfFYI9SLQenx0_vludp0oN9BSDe-mTfYNp5nS131cZRCKM\
AR3g_zzgkULu022xTJVsXfM1dsMYwEpGZp-GAvrlmRO6IathHW4aeo0QpaygOgfquQNYgS3Z8OJRSUDGnoY65g50d\
gvl1-ASbZX_r0_fNANLzXt_cnf0VXPrWdqvhuUSO561TsbTYg4qzcyDRV5vpjoUAxjFna06TJkeZR_OYMMcTtPRJO\
N3_bMvzp7MFoL20PRPxu8nnqxwLWNzoQCkExS2yWHq1YDNNL4C_PIuyC_2IUbbPuwNp8ir3MVDBq4QwuXbw6xFvbP\
sxOmZyH10xvpsnmokg",\
        "MIIDZjCCAk6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBEMRMwEQYKCZImiZPyLGQBGRYDb3JnMRYwFAYK\
CZImiZPyLGQBGRYGd2VicGtpMRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwHhcNMDIwNzEwMTAwMDAwWhcNMzAwNzEwM\
Dk1OTU5WjBEMRMwEQYKCZImiZPyLGQBGRYDb3JnMRYwFAYKCZImiZPyLGQBGRYGd2VicGtpMRUwEwYDVQQDEwxEZW\
1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMR4ROlJJyBUzQ92XDSzFuxiMjwFqsrKX\
uIksIXMypjg2QZF4PzyQ0pu32_LVKuoaqbT-bkRKFdpUvMKhzGQ3rMAthTUkhXpFJN5Bk2LTcGXoE0B9wPKn4C3cx\
bUMEtT94m8PKIjRoKm77Rvdd4vrG1GiCw98WriMtNbX_psYzr_RikIcpEUpm4PPXzPPFuBzYIeDFG50aPEJu6arup\
5b1w7SQe6lq_f_XhKYWENH1LcQOFsMoQ8oUS_WsYQ8aeT6_FxjMumjv4f9LanUHb73bBPA0xiqtEfNIuK1ZogXgqT\
0157tqbmg2-GCSz-dGZv3VbSyQPdqh5s8YEGEK873vAgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH\
_BAQDAgEGMB0GA1UdDgQWBBRaQnES9aDCSV_XOklJczxnqxI4_DAfBgNVHSMEGDAWgBRaQnES9aDCSV_XOklJczxn\
qxI4_DANBgkqhkiG9w0BAQsFAAOCAQEAHyxu0Z74ZYbWdy_fUtI9uIid_7F5AjbDdTzJcZgbSvyF3ZYVF62pRjSyx\
tIcCKbbr_oRPf5voYzlIP2UL7HGBB1WzKDnfP5sXWWEC5kYmo7NrYxTzbg22mS7nUpiro07qr1FTM1aCaJhu1Rqio\
UKX4omlilZqTkTq6lBmDOdN-5RyBoA28EV-stt3-NV1JzOxIFqEqJfMW1q4Bzg5RM_S4xy_jCj_hMSn2Etm5YoNVw\
ju2L86JZ8433SoemQWjl7qMHEJ1tTMEG9hR5DiE9j6STtbza-WbJHGqSdY_z1IsYbNgoZgYtJbRtZ4aObZb4FxflM\
TvObXiOInYgeKdK-Dw"\
  ]\
}';

var ecdsa_x509_sign =
'{\
    "prop1": 199,\
    "Signature": \
        {\
            "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",\
            "KeyInfo": \
                {\
                    "SignatureCertificate": \
                        {\
                            "Issuer": "CN=Demo Sub CA,DC=webpki,DC=org",\
                            "SerialNumber": 1377713637130,\
                            "Subject": "CN=example.com,O=Example Organization,C=US"\
                        },\
                    "X509CertificatePath": \
                        [\
                            "MIIClzCCAX-gAwIBAgIGAUDGIccKMA0GCSqGSIb3DQEBCwUAMEMxEzARBgoJkiaJk_IsZAEZFg\
NvcmcxFjAUBgoJkiaJk_IsZAEZFgZ3ZWJwa2kxFDASBgNVBAMTC0RlbW8gU3ViIENBMB4XDTEyMDEwMTAwMDAwMFoXDTIwMDcxMDA5N\
Tk1OVowQjELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFEV4YW1wbGUgT3JnYW5pemF0aW9uMRQwEgYDVQQDEwtleGFtcGxlLmNvbTBZMBMG\
ByqGSM49AgEGCCqGSM49AwEHA0IABECkenu7FrOpy7J2FGeO1vrtseQqJT2GsaExxK5UVKe1zhFXjF-V8OFjv_FdM9fqdqwkP_YUnx5\
epvvHh_-_cQWjXTBbMAkGA1UdEwQCMAAwDgYDVR0PAQH_BAQDAgP4MB0GA1UdDgQWBBR4YF2UOnLWDhOPLLuXYZum7xLMajAfBgNVHS\
MEGDAWgBRZXCF2vVvvaakHecbUVh7jS1yIVTANBgkqhkiG9w0BAQsFAAOCAQEAjBuZK2TcDhib12DSW8rW3kyjfQ3iYtjNSVd7vJ5jy\
I-0OYQ_NlhN4vVJx7Z02vnrBxv1Nh9swgT5Jpw0724KawGC4P-_bUEvKVz89tPMl9DaV98yQ2YN4cBfhcW3FpAoI4dzBbCzfEplsh9E\
k7VxuIgwPozl0AdqOmTjZ3hh54ApSq_PMwENDyCEzD6bvrCrqCjgWSYIQUIvQ7LfO2HAlEE9DcoV4mSl_8uiQ05hRdGmNYUHZVUua0H\
HX1h_nAS-IcS6_EDd89kEGrL3M92a5wqnIQvDLO2NBCXhHSxoPVyBzv0lIgaO0ixD-q5P2OszRBYG3uk9W_uNIHdoyQn19w",\
                            "MIIDZjCCAk6gAwIBAgICAMgwDQYJKoZIhvcNAQELBQAwRDETMBEGCgmSJomT8ixkARkWA29yZz\
EWMBQGCgmSJomT8ixkARkWBndlYnBraTEVMBMGA1UEAxMMRGVtbyBSb290IENBMB4XDTA1MDcxMDEwMDAwMFoXDTI1MDcxMDA5NTk1O\
VowQzETMBEGCgmSJomT8ixkARkWA29yZzEWMBQGCgmSJomT8ixkARkWBndlYnBraTEUMBIGA1UEAxMLRGVtbyBTdWIgQ0EwggEiMA0G\
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQI1w6lq0AsHbWMes8i_UGBeVQnlbzL2N8VyLjkbT3HXNHPUTjWWQElhoRzFA2xPaH--V\
_ecgr2Dkievrm-B5yIsdAL4oWWmgZ9KVMSfOrl5jy843p6AA55CHlP4j8v1uU1SpexIMUegDcNPlBwSRc0PPX-uqQ1STRg0kUgi4Bap\
7U5IRxTvp06adFXU4Bjr85ML7VZ3j-164t6mLnwF5RChJMlO7aVuz6TwxnWqeZytjFOei742dgbX9SHPVvytLtbFp4V_VFoEhaOXLZi\
OudPvpVwVdlfgE0AtiGHEWrfA74BU5XhME6UXzjcl3y3Ic304YGymo2jvmOwBki5wb3AgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8w\
DgYDVR0PAQH_BAQDAgEGMB0GA1UdDgQWBBRZXCF2vVvvaakHecbUVh7jS1yIVTAfBgNVHSMEGDAWgBRaQnES9aDCSV_XOklJczxnqxI\
4_DANBgkqhkiG9w0BAQsFAAOCAQEAMlPdBaZ_-AMDfFYI9SLQenx0_vludp0oN9BSDe-mTfYNp5nS131cZRCKMAR3g_zzgkULu022xT\
JVsXfM1dsMYwEpGZp-GAvrlmRO6IathHW4aeo0QpaygOgfquQNYgS3Z8OJRSUDGnoY65g50dgvl1-ASbZX_r0_fNANLzXt_cnf0VXPr\
WdqvhuUSO561TsbTYg4qzcyDRV5vpjoUAxjFna06TJkeZR_OYMMcTtPRJON3_bMvzp7MFoL20PRPxu8nnqxwLWNzoQCkExS2yWHq1YD\
NNL4C_PIuyC_2IUbbPuwNp8ir3MVDBq4QwuXbw6xFvbPsxOmZyH10xvpsnmokg",\
                            "MIIDZjCCAk6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBEMRMwEQYKCZImiZPyLGQBGRYDb3JnMR\
YwFAYKCZImiZPyLGQBGRYGd2VicGtpMRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwHhcNMDIwNzEwMTAwMDAwWhcNMzAwNzEwMDk1OTU5W\
jBEMRMwEQYKCZImiZPyLGQBGRYDb3JnMRYwFAYKCZImiZPyLGQBGRYGd2VicGtpMRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwggEiMA0G\
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCMR4ROlJJyBUzQ92XDSzFuxiMjwFqsrKXuIksIXMypjg2QZF4PzyQ0pu32_LVKuoaqbT-\
bkRKFdpUvMKhzGQ3rMAthTUkhXpFJN5Bk2LTcGXoE0B9wPKn4C3cxbUMEtT94m8PKIjRoKm77Rvdd4vrG1GiCw98WriMtNbX_psYzr_\
RikIcpEUpm4PPXzPPFuBzYIeDFG50aPEJu6arup5b1w7SQe6lq_f_XhKYWENH1LcQOFsMoQ8oUS_WsYQ8aeT6_FxjMumjv4f9LanUHb\
73bBPA0xiqtEfNIuK1ZogXgqT0157tqbmg2-GCSz-dGZv3VbSyQPdqh5s8YEGEK873vAgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8w\
DgYDVR0PAQH_BAQDAgEGMB0GA1UdDgQWBBRaQnES9aDCSV_XOklJczxnqxI4_DAfBgNVHSMEGDAWgBRaQnES9aDCSV_XOklJczxnqxI\
4_DANBgkqhkiG9w0BAQsFAAOCAQEAHyxu0Z74ZYbWdy_fUtI9uIid_7F5AjbDdTzJcZgbSvyF3ZYVF62pRjSyxtIcCKbbr_oRPf5voY\
zlIP2UL7HGBB1WzKDnfP5sXWWEC5kYmo7NrYxTzbg22mS7nUpiro07qr1FTM1aCaJhu1RqioUKX4omlilZqTkTq6lBmDOdN-5RyBoA2\
8EV-stt3-NV1JzOxIFqEqJfMW1q4Bzg5RM_S4xy_jCj_hMSn2Etm5YoNVwju2L86JZ8433SoemQWjl7qMHEJ1tTMEG9hR5DiE9j6STt\
bza-WbJHGqSdY_z1IsYbNgoZgYtJbRtZ4aObZb4FxflMTvObXiOInYgeKdK-Dw"\
                        ]\
                },\
            "SignatureValue": "MEUCIG89OH9pXHMi200H21_jHHh_yXWgfhByTYfit1MLic3YAiEA94tPtmBn89nLhTZhS8QGpjOzJ8eiuMMPgRYygrYCqbI"\
        }\
}';

var brainpool_bin = org.webpki.json.JSONParser.parse (brainpool).getPublicKey ();
var rsa_pk_bin = org.webpki.json.JSONParser.parse (rsa_pk).getPublicKey ();
var x509certpath_bin = org.webpki.json.JSONParser.parse (x509certpath).getX509CertificatePath ();

var canon_sign = new org.webpki.json.JSONObjectWriter (signature).serializeJSONObject (org.webpki.json.JSONOutputFormats.CANONICALIZED);

if (org.webpki.json.JSONObjectWriter._getCanonicalizedSubset (signature.root) != canon_sign)
{
    throw "Canon sign bug";
}
org.webpki.json.JSONObjectWriter.setCanonicalizationDebugMode (true);
var sign_decoder = signature.getSignature ();
console.debug (sign_decoder.getSignatureType ().toString ());
if (sign_decoder.getPublicKey ().length != 1) throw "Pubkey length";
sign_decoder = org.webpki.json.JSONParser.parse (ecdsa_x509_sign).getSignature ();
if (sign_decoder.getX509CertificatePath ().length != 3) throw "cert path length";

console.debug ("Successful");


